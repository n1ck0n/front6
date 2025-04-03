const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Временное хранилище пользователей (на практике — база данных)
const users = [];

// Файл кэша для /data
const CACHE_FILE = path.join(__dirname, 'dataCache.json');
const CACHE_TTL = 60 * 1000; // 1 минута

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: 'yourSecretKey', // замените на более надёжный секрет
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Статическая подача файлов фронтенда (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// Проверка наличия сессии для защищённых роутов
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/');
}

// POST /register – регистрация
app.post('/register', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) {
    return res.status(400).json({ error: 'Необходимо указать логин и пароль' });
  }
  // Проверка, существует ли пользователь
  if (users.find(u => u.login === login)) {
    return res.status(409).json({ error: 'Пользователь уже существует' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now(), login, password: hashedPassword };
    users.push(newUser);
    res.json({ message: 'Регистрация успешна' });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// POST /login – вход (создание сессии)
app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  const user = users.find(u => u.login === login);
  if (!user) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  // Создаем сессию
  req.session.userId = user.id;
  res.json({ message: 'Вход выполнен успешно' });
});

// GET /profile – защищённый роут (только для авторизованных)
app.get('/profile', isAuthenticated, (req, res) => {
  // Можно вернуть данные пользователя или отдать HTML-страницу
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// POST /logout – выход (удаление сессии)
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка при выходе' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Вы вышли из системы' });
  });
});

// GET /data – данные с кэшированием (файловый кэш на 1 минуту)
app.get('/data', (req, res) => {
  const now = Date.now();
  // Проверка наличия файла кэша и его валидности
  if (fs.existsSync(CACHE_FILE)) {
    const cacheContent = fs.readFileSync(CACHE_FILE, 'utf-8');
    try {
      const cache = JSON.parse(cacheContent);
      if (now - cache.timestamp < CACHE_TTL) {
        return res.json({ data: cache.data, cached: true });
      }
    } catch (err) {
      // Если ошибка парсинга, игнорируем кэш
    }
  }
  // Генерируем новые данные (например, случайное число и текущую дату)
  const newData = {
    random: Math.floor(Math.random() * 1000),
    date: new Date().toISOString()
  };
  const cacheToSave = { timestamp: now, data: newData };
  fs.writeFileSync(CACHE_FILE, JSON.stringify(cacheToSave));
  res.json({ data: newData, cached: false });
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});
