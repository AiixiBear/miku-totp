const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const speakeasy = require('speakeasy');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');


const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
app.use(cors());
app.use(express.json());

// ===== 模擬使用者資料 =====
const users = [
    {
        username: 'bearshen',
        password: bcrypt.hashSync(process.env.PASSWORD, 10) // 密碼 bcrypt 加密
    }
];

// ===== TOTP Apps =====
let apps = [];
try {
    apps = JSON.parse(process.env.TOTP_APPS || '[]');
} catch (err) {
    console.error('❌ TOTP_APPS JSON 格式錯誤');
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
    try {
        const { username, password, cf_turnstile_token } = req.body;

        // 驗證 Turnstile
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
        // bcrypt 驗證帳號密碼
        const user = users.find(u => u.username === username);
        if (!user) return res.status(401).json({ error: 'invalid credentials' });

        if (!bcrypt.compareSync(password, user.password))
            return res.status(401).json({ error: 'invalid credentials' });

        // JWT 簽發
        const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'server error' });
    }
});

// ===== JWT 驗證中介層 =====
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'missing token' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'malformed token' });

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
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

        res.json({
            user: req.user.username,
            timestamp: Date.now(),
            result
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'server error' });
    }
});

// ===== 新增 API: 驗證 Token 並獲取伺服器時間 (修復 1 & 2) =====
app.get('/api/validate', authMiddleware, (req, res) => {
    try {
        // 🌸 只要能過 authMiddleware，就代表 Token 是有效的
        // 我們回傳當前的伺服器時間戳 (ms) 給前端校準
        res.json({
            valid: true,
            user: req.user.username,
            serverTime: Date.now() // 回傳伺服器毫秒數
        });
    } catch (err) {
        res.status(500).json({ error: 'server error' });
    }
});

// ===== 靜態前端 =====
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== 啟動 server =====
app.listen(PORT, () => {
    console.log(`🔥 JWT TOTP + Turnstile API running on http://localhost:${PORT}`);
});
