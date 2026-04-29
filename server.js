require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key';

app.use(cors());
app.use(express.json());

// SQLite
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

// 🔹 Отправка кода (в консоли для демо)
app.post('/api/auth/send-code', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email обязателен' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 600000; // 10 мин
  db.run('INSERT OR REPLACE INTO verification_codes VALUES (?, ?, ?)',
    [email, code, expiresAt], (err) => {
      if (err) return res.status(500).json({ error: 'Ошибка БД' });
      console.log(`🔐 Код для ${email}: ${code}`);
      res.json({ message: 'Код отправлен (см. консоль сервера)', code });
    });
});

// 🔹 Проверка кода
app.post('/api/auth/verify-code', (req, res) => {
  const { email, code } = req.body;
  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], (err, row) => {
    if (err || !row || row.expires_at < Date.now()) return res.status(400).json({ error: 'Неверный или истёкший код' });
    res.json({ valid: true });
  });
});

// 🔹 Регистрация
app.post('/api/auth/register', async (req, res) => {
  const { email, password, code } = req.body;
  if (!email || !password || !code) return res.status(400).json({ error: 'Заполните все поля' });
  if (password.length < 8) return res.status(400).json({ error: 'Минимум 8 символов' });

  db.get('SELECT * FROM verification_codes WHERE email = ? AND code = ?', [email, code], async (err, row) => {
    if (err || !row || row.expires_at < Date.now()) return res.status(400).json({ error: 'Неверный код подтверждения' });
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashed], function(err) {
      if (err) return res.status(err.message.includes('UNIQUE') ? 409 : 500).json({ error: err.message.includes('UNIQUE') ? 'Email уже зарегистрирован' : 'Ошибка регистрации' });
      db.run('DELETE FROM verification_codes WHERE email = ?', [email]);
      const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });
      res.status(201).json({ token, user: { id: this.lastID, email } });
    });
  });
});

// 🔹 Вход
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

// 🔹 Прогресс обучения
app.get('/api/user/progress/:section', authenticate, (req, res) => {
  db.get('SELECT progress FROM user_progress WHERE user_id = ? AND section = ?', [req.user.id, req.params.section], (err, row) => {
    if (err) return res.status(500).json({ error: 'Ошибка чтения' });
    res.json({ progress: row ? JSON.parse(row.progress) : [] });
  });
});
app.put('/api/user/progress/:section', authenticate, (req, res) => {
  const { progress } = req.body;
  db.run('INSERT OR REPLACE INTO user_progress VALUES (?, ?, ?)',
    [req.user.id, req.params.section, JSON.stringify(progress)], (err) => {
      if (err) return res.status(500).json({ error: 'Ошибка сохранения' });
      res.json({ success: true });
    });
});

// 🔹 Сертификаты
app.get('/api/user/certificates', authenticate, (req, res) => {
  db.all('SELECT * FROM certificates WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, certs) => {
    if (err) return res.status(500).json({ error: 'Ошибка чтения' });
    res.json(certs);
  });
});
app.post('/api/user/certificates', authenticate, (req, res) => {
  const { type, score, date, number } = req.body;
  db.run('INSERT INTO certificates (user_id, type, score, date, number) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, type, score, date, number], function(err) {
      if (err) return res.status(500).json({ error: 'Ошибка сохранения' });
      res.status(201).json({ id: this.lastID });
    });
});

app.listen(PORT, () => console.log(`🚀 Сервер запущен: http://localhost:${PORT}`));