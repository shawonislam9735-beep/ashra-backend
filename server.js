'use strict';

require('dotenv').config();

const express     = require('express');
const cors        = require('cors');
const bcrypt      = require('bcrypt');
const jwt         = require('jsonwebtoken');
const rateLimit   = require('express-rate-limit');
const fs          = require('fs');
const path        = require('path');
const OpenAI      = require('openai');

const app  = express();
const PORT = process.env.PORT || 3000;

// Validate env
const REQUIRED_ENV = ['OPENAI_API_KEY', 'JWT_SECRET'];
REQUIRED_ENV.forEach(key => {
  if (!process.env[key]) {
    console.error(`Missing env: ${key}`);
    process.exit(1);
  }
});

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const JWT_SECRET = process.env.JWT_SECRET;
const BCRYPT_ROUNDS = 12;
const USERS_FILE = path.join(__dirname, 'users.json');

// System prompt
const SYSTEM_PROMPT = `You are ASHRA AI, a smart, human-like assistant. Keep responses concise, natural, and helpful.`;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
}));
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
});

// User storage
function readUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findUser(username) {
  return readUsers().find(u => u.username === username.toLowerCase());
}

// Sanitize
function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>?/gm, '').slice(0, 500);
}

function sanitizeUsername(str) {
  return String(str).replace(/[^a-zA-Z0-9_]/g, '').toLowerCase().slice(0, 32);
}

// Auth middleware
function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Auth required' });
  }

  try {
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Signup
app.post('/signup', authLimiter, async (req, res) => {
  try {
    const username = sanitizeUsername(req.body.username);
    const password = req.body.password;

    if (!username || password.length < 6)
      return res.status(400).json({ error: 'Invalid input' });

    if (findUser(username))
      return res.status(409).json({ error: 'User exists' });

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const users = readUsers();
    users.push({ username, passwordHash });
    writeUsers(users);

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, username });

  } catch {
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Login
app.post('/login', authLimiter, async (req, res) => {
  try {
    const username = sanitizeUsername(req.body.username);
    const password = req.body.password;

    const user = findUser(username);
    if (!user) return res.status(401).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Wrong password' });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, username });

  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Chat
app.post('/chat', requireAuth, chatLimiter, async (req, res) => {
  try {
    const { messages } = req.body;

    if (!messages || !Array.isArray(messages))
      return res.status(400).json({ error: 'Messages required' });

    const sanitizedMessages = messages.slice(-20).map(m => ({
      role: m.role,
      content: sanitizeText(m.content)
    }));

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        ...sanitizedMessages
      ],
      max_tokens: 1000
    });

    const reply = response.choices?.[0]?.message?.content || "No response";

    res.json({ reply });

  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'AI error' });
  }
});

// Me
app.get('/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username });
});

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', model: 'gpt-4o-mini' });
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start
app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});
