const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const speakeasy = require('speakeasy');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const winston = require('winston');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== 建立 logs 資料夾 =====
if (!fs.existsSync('logs')) fs.mkdirSync('logs');

// ===== 記憶體日誌（最新 100 筆，供 API 使用）=====
const memoryLogs = [];
const MAX_MEMORY_LOGS = 100;

function pushLog(entry) {
    memoryLogs.unshift(entry); // 新的放最前面
    if (memoryLogs.length > MAX_MEMORY_LOGS) memoryLogs.pop();
}

// ===== Logger（winston 寫檔）=====
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
            const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
            return `[${timestamp}] [${level.toUpperCase()}] ${message}${metaStr}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' })
    ]
});

// ===== HTML 跳脫（防 XSS 存入日誌）=====
function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

function sanitizeMeta(meta) {
    const clean = {};
    for (const [k, v] of Object.entries(meta)) {
        clean[k] = escapeHtml(String(v));
    }
    return clean;
}

// ===== 統一記錄函式 =====
function log(level, event, meta = {}) {
    const entry = {
        time: new Date().toISOString(),
        level,
        event: escapeHtml(event),
        ...sanitizeMeta(meta)   // ← 所有欄位都跳脫
    };
    pushLog(entry);
    logger[level](event, meta); // winston 寫原始值就好，不影響
}

// ===== 取得真實 IP（相容 Cloudflare / 反向代理）=====
function getClientIP(req) {
    return (
        req.headers['cf-connecting-ip'] ||
        req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.socket.remoteAddress
    );
}

// ===== Middleware =====
app.use(cors());
app.use(express.json());

// ===== 訪問日誌 Middleware =====
app.use((req, res, next) => {
    const ua = req.headers['user-agent'] || 'unknown';
    
    // 排除 Uptime Kuma 的監控流量，不記日誌
    if (ua.toLowerCase().includes('uptime-kuma')) {
        return next();
    }

    // 只記錄頁面訪問，避免 API 輪詢洗爆日誌
    if (req.path === '/' || req.path === '/index.html') {
        log('info', '訪問網站', {
            method: req.method,
            path: req.path,
            ip: getClientIP(req),
            userAgent: ua
        });
    }
    next();
});

// ===== 模擬使用者資料 =====
const users = [
    {
        username: 'bearshen',
        password: bcrypt.hashSync(process.env.PASSWORD, 10)
    }
];

// ===== TOTP Apps =====
let apps = [];
try {
    apps = JSON.parse(process.env.TOTP_APPS || '[]');
} catch (err) {
    logger.error('❌ TOTP_APPS JSON 格式錯誤');
    process.exit(1);
}

// ===== Cloudflare Turnstile 驗證 =====
async function verifyTurnstile(token) {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            secret: process.env.TURNSTILE_SECRET,
            response: token
        })
    });
    const data = await res.json();
    return data.success;
}

// ===== API: 登入生成 JWT =====
app.post('/api/login', async (req, res) => {
    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || 'unknown';

    try {
        const { username, password, cf_turnstile_token } = req.body;

        const user = users.find(u => u.username === username);
        if (!user) {
            log('warn', '登入失敗：帳號不存在', { username, ip, userAgent: ua });
            return res.status(401).json({ error: 'invalid credentials' });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            log('warn', '登入失敗：密碼錯誤', { username, ip, userAgent: ua });
            return res.status(401).json({ error: 'invalid credentials' });
        }

        const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '7d' });
        log('info', '登入成功', { username, ip, userAgent: ua });
        res.json({ token });
    } catch (err) {
        log('error', '登入發生錯誤', { ip, userAgent: ua, error: err.message });
        res.status(500).json({ error: 'server error' });
    }
});

// ===== JWT 驗證中介層（詳細記錄）=====
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || 'unknown';

    // 排除 Uptime Kuma，避免監控工具觸發未授權告警
    if (ua.toLowerCase().includes('uptime-kuma')) {
        if (!authHeader) return res.status(401).json({ error: 'missing token' });
        const token = authHeader.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'malformed token' });
        try {
            jwt.verify(token, process.env.JWT_SECRET);
            return next();
        } catch (err) {
            return res.status(401).json({ error: 'invalid token' });
        }
    }

    // 1. 完全沒有帶 Authorization 標頭
    if (!authHeader) {
        log('warn', '未授權的 API 存取嘗試（缺少 Token）', {
            method: req.method,
            path: req.path,
            ip,
            userAgent: ua,
            status: 'AUTH_MISSING_TOKEN'
        });
        return res.status(401).json({ error: 'missing token' });
    }

    const token = authHeader.split(' ')[1];
    
    // 2. 有帶標頭但格式錯誤（例如只寫了 Bearer 後面沒空白）
    if (!token) {
        log('warn', '未授權的 API 存取嘗試（Token 格式錯誤）', {
            method: req.method,
            path: req.path,
            ip,
            userAgent: ua,
            status: 'AUTH_MALFORMED_TOKEN'
        });
        return res.status(401).json({ error: 'malformed token' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        // 3. Token 存在但驗證失敗（過期、偽造、或密鑰不對）
        log('warn', '未授權的 API 存取嘗試（Token 驗證失敗）', {
            method: req.method,
            path: req.path,
            ip,
            userAgent: ua,
            error: err.message,
            status: 'AUTH_INVALID_TOKEN'
        });
        return res.status(401).json({ error: 'invalid or expired token' });
    }
}

// ===== API: 抓 TOTP =====
app.get('/api/totp', authMiddleware, (req, res) => {
    try {
        const result = apps.map(app => ({
            name: app.name,
            code: speakeasy.totp({
                secret: app.secret,
                encoding: 'base32',
                step: 30
            })
        }));
        res.json({ user: req.user.username, timestamp: Date.now(), result });
    } catch (err) {
        log('error', 'TOTP 發生錯誤', { error: err.message });
        res.status(500).json({ error: 'server error' });
    }
});

// ===== API: 驗證 Token 並獲取伺服器時間 =====
app.get('/api/validate', authMiddleware, (req, res) => {
    try {
        res.json({ valid: true, user: req.user.username, serverTime: Date.now() });
    } catch (err) {
        res.status(500).json({ error: 'server error' });
    }
});

// ===== API: 取得日誌（需登入）=====
app.get('/api/logs', authMiddleware, (req, res) => {
    res.json({ logs: memoryLogs });
});

// ===== 靜態前端 =====
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== 處理 404 錯誤與未授權路由探測 =====
app.use((req, res, next) => {
    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || 'unknown';

    // 記錄未知的路徑訪問，通常為掃描或誤入
    log('warn', '未知的路由訪問 (404)', {
        method: req.method,
        path: req.path,
        ip: ip,
        userAgent: ua
    });

    res.status(404).json({ error: 'not found' });
});

// ===== 啟動 server =====
app.listen(PORT, () => {
    log('info', '伺服器啟動', { port: PORT });
});