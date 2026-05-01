// server.js
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key';

app.use(cors());
app.use(express.json());

// ============================================================
// 📧 NODemailer — реальная отправка писем
// ============================================================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,           // например: smtp.gmail.com
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true', // true для 465, false для 587
  auth: {
    user: process.env.SMTP_USER,         // ваш email
    pass: process.env.SMTP_PASS          // пароль приложения
  }
});

// Проверка SMTP при старте
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ SMTP не настроен. Отправка кодов НЕ будет работать.');
    console.error('   Заполните .env: SMTP_HOST, SMTP_USER, SMTP_PASS');
  } else {
    console.log('✅ SMTP готов к отправке писем');
  }
});

// Функция отправки кода — БЕЗ fallback
async function sendVerificationEmail(email, code) {
  const mailOptions = {
    from: `"Готов к РФ" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
    to: email,
    subject: '🔐 Ваш код подтверждения — Готов к РФ',
    text: `Ваш код подтверждения: ${code}\n\nКод действителен 10 минут.\nЕсли вы не запрашивали код — проигнорируйте это письмо.`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;border:1px solid #e0e0e0;border-radius:8px">
        <h2 style="color:#2563eb;margin:0 0 20px">🇷🇺 Готов к РФ</h2>
        <p>Здравствуйте!</p>
        <p>Ваш код подтверждения:</p>
        <div style="background:#f3f4f6;padding:15px;border-radius:6px;text-align:center;font-size:24px;font-weight:bold;letter-spacing:3px;margin:20px 0">${code}</div>
        <p style="color:#6b7280;font-size:14px">Код действителен <strong>10 минут</strong>.</p>
        <p style="color:#6b7280;font-size:12px;margin-top:30px">Если вы не запрашивали этот код — просто проигнорируйте письмо.</p>
        <hr style="border:none;border-top:1px solid #e0e0e0;margin:30px 0">
        <p style="color:#9ca3af;font-size:11px">© 2024 Готов к РФ. Подготовка к жизни в России.</p>
      </div>
    `
  };
  return await transporter.sendMail(mailOptions);
}

// ============================================================
// SQLite
// ============================================================
const db = new sqlite3.Database('./app.db', (err) => {
  if (err) console.error('❌ Ошибка подключения к БД:', err);
  else console.log('✅ SQLite подключена');
});

// Инициализация таблиц
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

// Middleware авторизации
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Требуется авторизация' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Недействительный или истёкший токен' });
    req.user = user;
    next();
  });
};

// 🔹 Отправка кода — ТОЛЬКО через email, БЕЗ fallback
app.post('/api/auth/send-code', async (req, res) => {
  const { email } = req.body;
  
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Введите корректный email' });
  }

  // Проверка: настроен ли SMTP
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return res.status(503).json({ 
      error: 'Сервис отправки писем временно недоступен',
      message: 'Обратитесь к администратору'
    });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 600000; // 10 минут

  try {
    // Сохраняем код в БД
    await new Promise((resolve, reject) => {
      db.run('INSERT OR REPLACE INTO verification_codes VALUES (?, ?, ?)',
        [email, code, expiresAt], (err) => err ? reject(err) : resolve());
    });

    // Отправляем письмо — БЕЗ fallback
    await sendVerificationEmail(email, code);
    
    // ✅ Успех — код НЕ показываем в ответе
    console.log(`✉️ Код отправлен на ${email}`);
    res.json({ message: 'Код подтверждения отправлен на вашу электронную почту' });
    
  } catch (err) {
    console.error('❌ Ошибка отправки кода:', err.message);
    
    // Удаляем код из БД, если письмо не ушло
    db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
    
    res.status(500).json({ 
      error: 'Не удалось отправить код подтверждения',
      message: 'Попробуйте позже или проверьте адрес почты'
    });
  }
});

// 🔹 Проверка кода
app.post('/api/auth/verify-code', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Email и код обязательны' });
  
  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], (err, row) => {
    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
    if (!row) return res.status(400).json({ error: 'Неверный код' });
    if (row.expires_at < Date.now()) {
      db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
      return res.status(400).json({ error: 'Код истёк. Запросите новый' });
    }
    // Код верный — удаляем после использования
    db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
    res.json({ valid: true });
  });
});

// 🔹 Регистрация
app.post('/api/auth/register', async (req, res) => {
  const { email, password, code } = req.body;
  if (!email || !password || !code) return res.status(400).json({ error: 'Заполните все поля' });
  if (password.length < 8) return res.status(400).json({ error: 'Минимум 8 символов' });

  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], async (err, row) => {
    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
    if (!row || row.expires_at < Date.now()) {
      if (row && row.expires_at < Date.now()) {
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
      }
      return res.status(400).json({ error: 'Неверный или истёкший код' });
    }

    try {
      const hashed = await bcrypt.hash(password, 10);
      db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashed], function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'Email уже зарегистрирован' });
          }
          return res.status(500).json({ error: 'Ошибка регистрации' });
        }
        db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
        const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, user: { id: this.lastID, email } });
      });
    } catch (e) {
      console.error('❌ Ошибка хеширования:', e);
      res.status(500).json({ error: 'Внутренняя ошибка' });
    }
  });
});

// 🔹 Вход
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Ошибка сервера' });
    if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });
    
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  });
});

// 🔹 Прогресс обучения
app.get('/api/user/progress/:section', authenticate, (req, res) => {
  db.get('SELECT progress FROM user_progress WHERE user_id = ? AND section = ?', 
    [req.user.id, req.params.section], (err, row) => {
      if (err) return res.status(500).json({ error: 'Ошибка чтения' });
      res.json({ progress: row ? JSON.parse(row.progress) : [] });
    });
});

app.put('/api/user/progress/:section', authenticate, (req, res) => {
  const { progress } = req.body;
  if (!Array.isArray(progress)) return res.status(400).json({ error: 'Прогресс должен быть массивом' });
  
  db.run('INSERT OR REPLACE INTO user_progress VALUES (?, ?, ?)',
    [req.user.id, req.params.section, JSON.stringify(progress)], (err) => {
      if (err) return res.status(500).json({ error: 'Ошибка сохранения' });
      res.json({ success: true });
    });
});

// 🔹 Сертификаты
app.get('/api/user/certificates', authenticate, (req, res) => {
  db.all('SELECT id, type, score, date, number, created_at FROM certificates WHERE user_id = ? ORDER BY created_at DESC', 
    [req.user.id], (err, certs) => {
      if (err) return res.status(500).json({ error: 'Ошибка чтения' });
      res.json(certs);
    });
});

app.post('/api/user/certificates', authenticate, (req, res) => {
  const { type, score, date, number } = req.body;
  if (!type || score === undefined || !date || !number) {
    return res.status(400).json({ error: 'Заполните все поля сертификата' });
  }
  
  db.run('INSERT INTO certificates (user_id, type, score, date, number) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, type, score, date, number], function(err) {
      if (err) return res.status(500).json({ error: 'Ошибка сохранения' });
      res.status(201).json({ id: this.lastID });
    });
});

// 🔹 Health check
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен: http://localhost:${PORT}`);
  console.log(`📧 SMTP: ${process.env.SMTP_USER ? 'настроен' : '⚠️ НЕ настроен — отправка кодов НЕ работает'}`);
});
