import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import express from 'express';
import helmet from 'helmet';
import Database from 'better-sqlite3';
import dotenv from 'dotenv';

dotenv.config();

const scryptAsync = promisify(crypto.scrypt);
const SESSION_COOKIE = 'capri_session';
const SESSION_MAX_AGE = 1000 * 60 * 60 * 24 * 14;
const MAX_TEXT_CHARS = 12000;

function hashValue(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function cleanText(value, maxLength = MAX_TEXT_CHARS) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLength);
}

function createDatabase(filePath) {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const db = new Database(resolved);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      disabled INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT,
      csrf_token TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS preferences (
      user_id TEXT PRIMARY KEY,
      data TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS memories (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('short', 'long')),
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      done INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      event TEXT NOT NULL,
      detail TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_memories_user ON memories(user_id, updated_at DESC);
  `);
  return db;
}

function makeSession(db, userId = null) {
  const token = crypto.randomBytes(32).toString('base64url');
  const csrfToken = crypto.randomBytes(24).toString('base64url');
  const now = Date.now();
  db.prepare('INSERT INTO sessions(token_hash, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(hashValue(token), userId, csrfToken, now + SESSION_MAX_AGE, new Date(now).toISOString());
  return { token, csrfToken };
}

function cookieOptions(isProduction) {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_MAX_AGE
  };
}

const rateLimitMap = new Map();
function rateLimit({ windowMs = 60_000, max = 60 } = {}) {
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || 'unknown';
    const entry = rateLimitMap.get(key) || { count: 0, until: now + windowMs };
    if (entry.until <= now) {
      entry.count = 0;
      entry.until = now + windowMs;
    }
    entry.count += 1;
    rateLimitMap.set(key, entry);
    if (entry.count > max) {
      return res.status(429).json({ error: 'Muitas requisições. Tente novamente em alguns segundos.' });
    }
    next();
  };
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function createApp(options = {}) {
  const dbPath = options.dbPath || process.env.DATABASE_PATH || './data/pulse.sqlite';
  const db = createDatabase(dbPath);
  const app = express();
  const isProduction = options.production ?? process.env.NODE_ENV === 'production';
  const publicDir = path.resolve(options.publicDir || './public');
  const groqApiKey = options.groqApiKey ?? process.env.GROQ_API_KEY || '';
  const groqModel = options.groqModel ?? process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
  const adminBootstrapToken = options.adminBootstrapToken ?? process.env.ADMIN_BOOTSTRAP_TOKEN || '';

  app.disable('x-powered-by');
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", 'https://api.groq.com']
      }
    }
  }));
  app.use(express.json({ limit: '1mb' }));
  app.use(rateLimit({ max: 250 }));

  app.use((req, res, next) => {
    const rawCookie = req.headers.cookie || '';
    const match = rawCookie.match(/(?:^|;\s*)capri_session=([^;]+)/);
    const token = match ? decodeURIComponent(match[1]) : '';

    if (!token) {
      req.session = null;
      req.sessionRecord = null;
      return next();
    }

    const row = db.prepare('SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, u.email, u.role, u.disabled FROM sessions s LEFT JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').get(hashValue(token));
    if (!row || row.expires_at <= Date.now()) {
      if (row) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(row.token_hash);
      req.session = null;
      req.sessionRecord = null;
      return next();
    }

    if (row.disabled === 1) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(row.token_hash);
      req.session = null;
      req.sessionRecord = null;
      return next();
    }

    req.session = token;
    req.sessionRecord = row;
    next();
  });

  const requireAuth = (req, res, next) => {
    if (!req.sessionRecord || !req.sessionRecord.user_id) {
      return res.status(401).json({ error: 'Faça login para continuar.' });
    }
    next();
  };

  const requireCsrf = (req, res, next) => {
    if (!req.sessionRecord) {
      return res.status(403).json({ error: 'Sessão inválida.' });
    }
    const expected = req.sessionRecord.csrf_token;
    const received = req.get('x-csrf-token') || '';
    if (!safeEqual(received, expected)) {
      return res.status(403).json({ error: 'Token de segurança inválido.' });
    }
    next();
  };

  const requireAdmin = (req, res, next) => {
    if (!req.sessionRecord || req.sessionRecord.role !== 'admin') {
      return res.status(403).json({ error: 'Acesso administrativo necessário.' });
    }
    next();
  };

  const audit = (userId, event, detail = '') => {
    db.prepare('INSERT INTO audit_logs(id, user_id, event, detail, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(crypto.randomUUID(), userId || null, event, cleanText(detail, 500), new Date().toISOString());
  };

  const setSessionCookie = (res, token) => {
    res.cookie(SESSION_COOKIE, token, cookieOptions(isProduction));
  };

  app.get('/api/health', (req, res) => {
    res.json({ ok: true, service: 'capri-ai', aiConfigured: Boolean(groqApiKey), timestamp: new Date().toISOString() });
  });

  app.get('/api/session', (req, res) => {
    if (!req.sessionRecord) {
      const session = makeSession(db);
      setSessionCookie(res, session.token);
      return res.json({ authenticated: false, csrfToken: session.csrfToken, user: null, aiConfigured: Boolean(groqApiKey) });
    }

    res.json({
      authenticated: true,
      csrfToken: req.sessionRecord.csrf_token,
      user: {
        id: req.sessionRecord.user_id,
        email: req.sessionRecord.email,
        role: req.sessionRecord.role
      },
      aiConfigured: Boolean(groqApiKey)
    });
  });

  app.post('/api/auth/register', rateLimit({ max: 20, windowMs: 10 * 60_000 }), async (req, res) => {
    const email = cleanText(req.body?.email || '', 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) {
      return res.status(400).json({ error: 'Informe um e-mail válido e uma senha com pelo menos 12 caracteres.' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const derived = await scryptAsync(password, salt, 64);
    const userId = crypto.randomUUID();
    const now = new Date().toISOString();

    db.prepare('INSERT INTO users(id, email, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(userId, email, derived.toString('hex'), salt, 'user', now);

    db.prepare('INSERT INTO preferences(user_id, data, updated_at) VALUES (?, ?, ?)')
      .run(userId, JSON.stringify({ theme: 'midnight', personality: 'Clara, objetiva e útil.', voiceEnabled: false }), now);

    const session = makeSession(db, userId);
    setSessionCookie(res, session.token);
    audit(userId, 'auth.register');

    res.status(201).json({ user: { id: userId, email, role: 'user' }, csrfToken: session.csrfToken });
  });

  app.post('/api/auth/login', rateLimit({ max: 20, windowMs: 10 * 60_000 }), async (req, res) => {
    const email = cleanText(req.body?.email || '', 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const hash = await scryptAsync(password, user.password_salt, 64);
    const passwordMatches = safeEqual(hash.toString('hex'), user.password_hash);

    if (!passwordMatches || user.disabled === 1) {
      audit(null, 'auth.login_failed', email);
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const session = makeSession(db, user.id);
    setSessionCookie(res, session.token);
    audit(user.id, 'auth.login');
    res.json({ user: { id: user.id, email: user.email, role: user.role }, csrfToken: session.csrfToken });
  });

  app.post('/api/auth/logout', requireAuth, requireCsrf, (req, res) => {
    if (req.session) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashValue(req.session));
    }
    res.clearCookie(SESSION_COOKIE, { path: '/', httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.status(204).end();
  });

  app.get('/api/preferences', requireAuth, (req, res) => {
    const row = db.prepare('SELECT data FROM preferences WHERE user_id = ?').get(req.sessionRecord.user_id);
    res.json(JSON.parse(row?.data || '{}'));
  });

  app.put('/api/preferences', requireAuth, requireCsrf, (req, res) => {
    const current = JSON.parse(db.prepare('SELECT data FROM preferences WHERE user_id = ?').get(req.sessionRecord.user_id)?.data || '{}');
    const next = { ...current, ...(req.body || {}) };
    const now = new Date().toISOString();
    db.prepare('INSERT INTO preferences(user_id, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at')
      .run(req.sessionRecord.user_id, JSON.stringify(next), now);
    res.json(next);
  });

  app.get('/api/conversations', requireAuth, (req, res) => {
    const rows = db.prepare('SELECT id, title, created_at, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC').all(req.sessionRecord.user_id);
    res.json(rows);
  });

  app.post('/api/conversations', requireAuth, requireCsrf, (req, res) => {
    const title = cleanText(req.body?.title || '', 200) || 'Nova conversa';
    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO conversations(id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, req.sessionRecord.user_id, title, now, now);
    res.status(201).json({ id, title, created_at: now, updated_at: now, messages: [] });
  });

  app.get('/api/conversations/:id', requireAuth, (req, res) => {
    const conversation = db.prepare('SELECT id, title, created_at, updated_at FROM conversations WHERE id = ? AND user_id = ?').get(req.params.id, req.sessionRecord.user_id);
    if (!conversation) return res.status(404).json({ error: 'Conversa não encontrada.' });
    const messages = db.prepare('SELECT id, role, content, created_at FROM messages WHERE conversation_id = ? ORDER BY created_at ASC').all(req.params.id);
    res.json({ ...conversation, messages });
  });

  app.patch('/api/conversations/:id', requireAuth, requireCsrf, (req, res) => {
    const title = cleanText(req.body?.title || '', 200);
    if (!title) return res.status(400).json({ error: 'Título inválido.' });
    const result = db.prepare('UPDATE conversations SET title = ?, updated_at = ? WHERE id = ? AND user_id = ?').run(title, new Date().toISOString(), req.params.id, req.sessionRecord.user_id);
    if (!result.changes) return res.status(404).json({ error: 'Conversa não encontrada.' });
    res.json({ ok: true, id: req.params.id, title });
  });

  app.delete('/api/conversations/:id', requireAuth, requireCsrf, (req, res) => {
    const result = db.prepare('DELETE FROM conversations WHERE id = ? AND user_id = ?').run(req.params.id, req.sessionRecord.user_id);
    if (!result.changes) return res.status(404).json({ error: 'Conversa não encontrada.' });
    res.status(204).end();
  });

  app.post('/api/chat', requireAuth, requireCsrf, async (req, res) => {
    const conversationId = cleanText(req.body?.conversationId || '', 100);
    const message = cleanText(req.body?.message || '', MAX_TEXT_CHARS);

    if (!conversationId || !message) {
      return res.status(400).json({ error: 'Mensagem e conversa são obrigatórias.' });
    }

    const conversation = db.prepare('SELECT id FROM conversations WHERE id = ? AND user_id = ?').get(conversationId, req.sessionRecord.user_id);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversa não encontrada.' });
    }

    if (!groqApiKey) {
      return res.status(503).json({ error: 'Groq ainda não está configurado no backend. Defina GROQ_API_KEY no ambiente do servidor.' });
    }

    const now = new Date().toISOString();
    const userMessageId = crypto.randomUUID();
    db.prepare('INSERT INTO messages(id, conversation_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(userMessageId, conversationId, 'user', message, now);

    const existingTitle = db.prepare('SELECT title FROM conversations WHERE id = ?').get(conversationId)?.title || 'Nova conversa';
    const suggestedTitle = existingTitle === 'Nova conversa' ? message.slice(0, 60) : existingTitle;
    db.prepare('UPDATE conversations SET title = ?, updated_at = ? WHERE id = ?').run(suggestedTitle, now, conversationId);

    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    res.write(`event: start\ndata: ${JSON.stringify({ messageId: userMessageId })}\n\n`);

    try {
      const preferenceRow = db.prepare('SELECT data FROM preferences WHERE user_id = ?').get(req.sessionRecord.user_id);
      const preferences = JSON.parse(preferenceRow?.data || '{}');
      const recentMessages = db.prepare('SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 12').all(conversationId).reverse();
      const memoryRows = db.prepare('SELECT content, kind FROM memories WHERE user_id = ? ORDER BY updated_at DESC LIMIT 8').all(req.sessionRecord.user_id);
      const context = memoryRows.length ? '\nMemórias: ' + memoryRows.map((row) => `[${row.kind}] ${row.content}`).join(' | ') : '';

      const payload = {
        model: groqModel,
        temperature: 0.7,
        messages: [
          {
            role: 'system',
            content: `Você é Capri, uma IA confiável e útil. Personalidade: ${preferences.personality || 'clara, objetiva e amigável'}. Responda em português do Brasil, seja direta e profissional.${context}`
          },
          ...recentMessages
        ],
        stream: true
      };

      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${groqApiKey}`
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const detail = await response.text();
        audit(req.sessionRecord.user_id, 'ai.provider_error', detail.slice(0, 200));
        res.write(`event: error\ndata: ${JSON.stringify({ error: 'Falha na comunicação com o provedor Groq.' })}\n\n`);
        return res.end();
      }

      const reader = response.body?.getReader();
      if (!reader) {
        res.write(`event: error\ndata: ${JSON.stringify({ error: 'Não foi possível abrir a resposta em streaming.' })}\n\n`);
        return res.end();
      }

      const decoder = new TextDecoder();
      let buffer = '';
      let fullReply = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data:')) continue;
          const payloadText = trimmed.slice(5).trim();
          if (!payloadText || payloadText === '[DONE]') continue;

          try {
            const chunk = JSON.parse(payloadText);
            const delta = chunk.choices?.[0]?.delta?.content || '';
            if (delta) {
              fullReply += delta;
              res.write(`event: delta\ndata: ${JSON.stringify({ text: delta })}\n\n`);
            }
          } catch {
            // ignore malformed chunks and continue
          }
        }
      }

      if (fullReply) {
        const assistantId = crypto.randomUUID();
        const assistantAt = new Date().toISOString();
        db.prepare('INSERT INTO messages(id, conversation_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)')
          .run(assistantId, conversationId, 'assistant', fullReply, assistantAt);
        db.prepare('UPDATE conversations SET updated_at = ? WHERE id = ?').run(assistantAt, conversationId);
        res.write(`event: done\ndata: ${JSON.stringify({ assistantId, createdAt: assistantAt })}\n\n`);
        audit(req.sessionRecord.user_id, 'ai.response_generated');
      }

      res.end();
    } catch (error) {
      audit(req.sessionRecord.user_id, 'ai.request_error', error instanceof Error ? error.message : 'unknown');
      res.write(`event: error\ndata: ${JSON.stringify({ error: 'A resposta não pôde ser concluída.' })}\n\n`);
      res.end();
    }
  });

  app.get('/api/memories', requireAuth, (req, res) => {
    const rows = db.prepare('SELECT id, kind, content, created_at, updated_at FROM memories WHERE user_id = ? ORDER BY updated_at DESC').all(req.sessionRecord.user_id);
    res.json(rows);
  });

  app.post('/api/memories', requireAuth, requireCsrf, (req, res) => {
    const content = cleanText(req.body?.content || '', 1500);
    const kind = req.body?.kind === 'short' ? 'short' : 'long';
    if (!content) return res.status(400).json({ error: 'Memória vazia.' });

    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO memories(id, user_id, kind, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, req.sessionRecord.user_id, kind, content, now, now);

    res.status(201).json({ id, kind, content, created_at: now, updated_at: now });
  });

  app.get('/api/tasks', requireAuth, (req, res) => {
    const rows = db.prepare('SELECT id, title, done, created_at, updated_at FROM tasks WHERE user_id = ? ORDER BY updated_at DESC').all(req.sessionRecord.user_id);
    res.json(rows);
  });

  app.post('/api/tasks', requireAuth, requireCsrf, (req, res) => {
    const title = cleanText(req.body?.title || '', 300);
    if (!title) return res.status(400).json({ error: 'Tarefa inválida.' });
    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO tasks(id, user_id, title, done, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)')
      .run(id, req.sessionRecord.user_id, title, now, now);
    res.status(201).json({ id, title, done: 0, created_at: now, updated_at: now });
  });

  app.patch('/api/tasks/:id', requireAuth, requireCsrf, (req, res) => {
    const title = req.body?.title ? cleanText(req.body.title, 300) : null;
    const done = typeof req.body?.done === 'boolean' ? (req.body.done ? 1 : 0) : null;
    const setClauses = [];
    const values = [];

    if (title) { setClauses.push('title = ?'); values.push(title); }
    if (done !== null) { setClauses.push('done = ?'); values.push(done); }

    if (!setClauses.length) return res.status(400).json({ error: 'Nenhuma alteração informada.' });

    setClauses.push('updated_at = ?');
    values.push(new Date().toISOString(), req.params.id, req.sessionRecord.user_id);

    const result = db.prepare(`UPDATE tasks SET ${setClauses.join(', ')} WHERE id = ? AND user_id = ?`).run(...values);
    if (!result.changes) return res.status(404).json({ error: 'Tarefa não encontrada.' });
    res.json({ ok: true });
  });

  app.get('/api/notes', requireAuth, (req, res) => {
    const rows = db.prepare('SELECT id, title, body, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC').all(req.sessionRecord.user_id);
    res.json(rows);
  });

  app.post('/api/notes', requireAuth, requireCsrf, (req, res) => {
    const title = cleanText(req.body?.title || '', 200) || 'Nota sem título';
    const body = cleanText(req.body?.body || '', 20000);
    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO notes(id, user_id, title, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, req.sessionRecord.user_id, title, body, now, now);
    res.status(201).json({ id, title, body, created_at: now, updated_at: now });
  });

  app.patch('/api/notes/:id', requireAuth, requireCsrf, (req, res) => {
    const title = cleanText(req.body?.title || '', 200) || 'Nota sem título';
    const body = cleanText(req.body?.body || '', 20000);
    const result = db.prepare('UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ? AND user_id = ?')
      .run(title, body, new Date().toISOString(), req.params.id, req.sessionRecord.user_id);
    if (!result.changes) return res.status(404).json({ error: 'Nota não encontrada.' });
    res.json({ ok: true });
  });

  app.post('/api/admin/bootstrap', rateLimit({ max: 5, windowMs: 60 * 60_000 }), async (req, res) => {
    const provided = req.get('x-admin-bootstrap') || '';
    if (!adminBootstrapToken || !safeEqual(provided, adminBootstrapToken)) {
      return res.status(404).json({ error: 'Rota não encontrada.' });
    }

    const exists = db.prepare('SELECT 1 FROM users WHERE role = ? LIMIT 1').get('admin');
    if (exists) return res.status(409).json({ error: 'Administrador já configurado.' });

    const email = cleanText(req.body?.email || '', 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 16) {
      return res.status(400).json({ error: 'E-mail inválido ou senha insuficiente; mínimo de 16 caracteres.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await scryptAsync(password, salt, 64);
    const userId = crypto.randomUUID();
    const now = new Date().toISOString();

    db.prepare('INSERT INTO users(id, email, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(userId, email, hash.toString('hex'), salt, 'admin', now);

    const session = makeSession(db, userId);
    setSessionCookie(res, session.token);
    audit(userId, 'admin.bootstrap');
    res.status(201).json({ user: { id: userId, email, role: 'admin' }, csrfToken: session.csrfToken });
  });

  app.get('/api/admin/overview', requireAuth, requireAdmin, (req, res) => {
    const overview = {
      users: db.prepare('SELECT COUNT(*) as total FROM users').get().total,
      conversations: db.prepare('SELECT COUNT(*) as total FROM conversations').get().total,
      messages: db.prepare('SELECT COUNT(*) as total FROM messages').get().total,
      aiConfigured: Boolean(groqApiKey),
      provider: groqApiKey ? 'Groq' : 'not_configured',
      model: groqApiKey ? groqModel : null
    };
    res.json(overview);
  });

  app.use(express.static(publicDir));

  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    res.sendFile(path.join(publicDir, 'index.html'), (error) => {
      if (error) next(error);
    });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  });

  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const app = createApp();
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    console.log(`CAPRI AI running on http://localhost:${port}`);
  });
}
