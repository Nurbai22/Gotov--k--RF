require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key';

app.use(cors());
app.use(express.json());

// 🔥 ВАЖНО: Раздаём статические файлы (HTML, CSS, JS)
app.use(express.static('.'));

// 📧 NODemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

transporter.verify((error, success) => {
  if (error) {
    console.error('❌ SMTP не настроен:', error.message);
  } else {
    console.log('✅ SMTP готов');
  }
});

async function sendVerificationEmail(email, code) {
  const mailOptions = {
    from: `"Готов к РФ" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
    to: email,
    subject: '🔐 Ваш код подтверждения',
    html: `
      <div style="font-family:Arial;max-width:500px;margin:0 auto;padding:20px;">
        <h2 style="color:#2563eb">🇷🇺 Готов к РФ</h2>
        <p>Ваш код подтверждения:</p>
        <div style="background:#f3f4f6;padding:15px;border-radius:6px;text-align:center;font-size:24px;font-weight:bold;letter-spacing:3px;margin:20px 0">${code}</div>
        <p style="color:#6b7280">Код действителен 10 минут.</p>
      </div>
    `
  };
  return await transporter.sendMail(mailOptions);
}

// SQLite
const db = new sqlite3.Database('./app.db', (err) => {
  if (err) console.error('❌ Ошибка БД:', err);
  else console.log('✅ SQLite подключена');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS user_progress (
    user_id INTEGER,
    section TEXT NOT NULL,
    progress TEXT NOT NULL,
    PRIMARY KEY(user_id, section),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    score INTEGER NOT NULL,
    date TEXT NOT NULL,
    number TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
});

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Требуется авторизация' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Недействительный токен' });
    req.user = user;
    next();
  });
};

// API Routes
app.post('/api/auth/send-code', async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Введите корректный email' });
  }
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return res.status(503).json({ error: 'Сервис email временно недоступен' });
  }
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 600000;
  try {
    await new Promise((resolve, reject) => {
      db.run('INSERT OR REPLACE INTO verification_codes VALUES (?, ?, ?)',
        [email, code, expiresAt], (err) => err ? reject(err) : resolve());
    });
    await sendVerificationEmail(email, code);
    console.log(`✉️ Код отправлен на ${email}`);
    res.json({ message: 'Код отправлен на email' });
  } catch (err) {
    console.error('❌ Ошибка:', err.message);
    db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
    res.status(500).json({ error: 'Не удалось отправить код' });
  }
});

app.post('/api/auth/verify-code', (req, res) => {
  const { email, code } = req.body;
  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], (err, row) => {
    if (err || !row || row.expires_at < Date.now()) {
      return res.status(400).json({ error: 'Неверный или истёкший код' });
    }
    db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
    res.json({ valid: true });
  });
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password, code } = req.body;
  if (!email || !password || !code) return res.status(400).json({ error: 'Заполните все поля' });
  if (password.length < 8) return res.status(400).json({ error: 'Минимум 8 символов' });
  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], async (err, row) => {
    if (err || !row || row.expires_at < Date.now()) {
      return res.status(400).json({ error: 'Неверный код' });
    }
    try {
      const hashed = await bcrypt.hash(password, 10);
      db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashed], function(err) {
        if (err) return res.status(409).json({ error: 'Email уже зарегистрирован' });
        const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, user: { id: this.lastID, email } });
      });
    } catch (e) {
      res.status(500).json({ error: 'Ошибка регистрации' });
    }
  });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Неверный email или пароль' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  });
});

app.get('/api/user/progress/:section', authenticate, (req, res) => {
  db.get('SELECT progress FROM user_progress WHERE user_id = ? AND section = ?', 
    [req.user.id, req.params.section], (err, row) => {
      res.json({ progress: row ? JSON.parse(row.progress) : [] });
    });
});

app.put('/api/user/progress/:section', authenticate, (req, res) => {
  db.run('INSERT OR REPLACE INTO user_progress VALUES (?, ?, ?)',
    [req.user.id, req.params.section, JSON.stringify(req.body.progress)], (err) => {
      res.json({ success: true });
    });
});

app.get('/api/user/certificates', authenticate, (req, res) => {
  db.all('SELECT * FROM certificates WHERE user_id = ? ORDER BY created_at DESC', 
    [req.user.id], (err, certs) => res.json(certs || []));
});

app.post('/api/user/certificates', authenticate, (req, res) => {
  db.run('INSERT INTO certificates (user_id, type, score, date, number) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, req.body.type, req.body.score, req.body.date, req.body.number], 
    function(err) { res.status(201).json({ id: this.lastID }); });
});

// 🔥 ВАЖНО: Главная страница — отдаём index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 🔥 ВАЖНО: Все остальные маршруты — тоже index.html (для SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`📧 SMTP: ${process.env.SMTP_USER ? 'настроен' : 'НЕ настроен'}`);
});
