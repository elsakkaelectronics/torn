require('express-async-errors');
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'torn-loss-manager-secret';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});
app.use(morgan('combined'));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
app.use('/api', limiter);

// ─── DATABASE ──────────────────────────────────────────────────────
const db = new sqlite3.Database('torn_loss_manager.db');
function run(sql, ...params) {
  return new Promise((resolve, reject) => {
    db.run(sql, ...params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, ...params) {
  return new Promise((resolve, reject) => {
    db.get(sql, ...params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function all(sql, ...params) {
  return new Promise((resolve, reject) => {
    db.all(sql, ...params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}
function exec(sql) {
  return new Promise((resolve, reject) => {
    db.exec(sql, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

// ─── INIT DB ──────────────────────────────────────────────────────
async function initDb() {
  try {
    await run('PRAGMA foreign_keys = ON');
    const schema = `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        torn_id INTEGER UNIQUE,
        api_key TEXT,
        username TEXT,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS user_settings (
        user_id INTEGER PRIMARY KEY,
        energy INTEGER DEFAULT 100,
        max_energy INTEGER DEFAULT 150,
        interval INTEGER DEFAULT 600,
        tick_time INTEGER DEFAULT 0,
        full_time INTEGER DEFAULT 0,
        profit INTEGER DEFAULT 0,
        total_hits INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        buyer TEXT NOT NULL,
        buyer_id INTEGER,
        loser TEXT NOT NULL,
        price INTEGER NOT NULL,
        total INTEGER NOT NULL,
        remaining INTEGER NOT NULL,
        status TEXT DEFAULT 'open',
        hitter_id INTEGER,
        paid BOOLEAN DEFAULT 0,
        reported BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (hitter_id) REFERENCES users(id)
      );
      CREATE TABLE IF NOT EXISTS receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        log_id TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS hit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        buyer TEXT,
        loser TEXT,
        price INTEGER,
        energy_used INTEGER DEFAULT 25,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        log_data TEXT,
        timestamp INTEGER,
        details TEXT,
        fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
    `;
    await exec(schema);
    console.log('✅ Tables created');

    const existingAdmin = await get('SELECT id FROM users WHERE torn_id = 0');
    if (!existingAdmin) {
      await run('INSERT INTO users (torn_id, username, role) VALUES (?, ?, ?)', 0, 'admin', 'admin');
      const admin = await get('SELECT id FROM users WHERE torn_id = 0');
      await run('INSERT INTO user_settings (user_id) VALUES (?)', admin.id);
      console.log('✅ Admin user created (nightmare / qwerty)');
    }
  } catch (e) {
    console.error('❌ Database init error:', e.message);
    throw e;
  }
}
initDb().catch(console.error);

const cache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// ─── UNIVERSAL AUTHENTICATION ─────────────────────────────────────
async function authenticate(req, res, next) {
  let user = null;
  const apiKey = req.headers['x-api-key'];
  const token = req.headers.authorization?.split(' ')[1];

  // Try API key
  if (apiKey) {
    try { user = await get('SELECT * FROM users WHERE api_key = ?', apiKey); } catch (e) {}
  }
  // Try JWT token
  if (!user && token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      user = await get('SELECT * FROM users WHERE id = ?', decoded.id);
    } catch (e) {}
  }
  // Try query param (debug)
  if (!user) {
    const queryKey = req.query['apiKey'] || req.query['X-API-Key'];
    if (queryKey) user = await get('SELECT * FROM users WHERE api_key = ?', queryKey);
  }

  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  req.user = user;

  // Ensure user_settings exists
  const settings = await get('SELECT * FROM user_settings WHERE user_id = ?', user.id);
  if (!settings) {
    await run('INSERT INTO user_settings (user_id) VALUES (?)', user.id);
  }

  next();
}

// ─── ROUTES ─────────────────────────────────────────────────────────

// Admin login
// ─── Add this table to initDb() ──────────────────────────────────
// In initDb(), inside the schema string:
CREATE TABLE IF NOT EXISTS blacklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  torn_id INTEGER,
  reason TEXT,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, torn_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (created_by) REFERENCES users(id)
);

// ─── New Admin Routes ─────────────────────────────────────────────

// ─── ADMIN VERIFY (manual receipt) ──────────────────────────────
app.post('/api/admin/requests/:id/verify', requireAdmin, async (req, res) => {
  const { log_id, message } = req.body;
  const reqData = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });

  const receiptMsg = message || `Admin verified hit against ${reqData.loser}. Log ID: ${log_id || 'manual'}`;
  const result = await run(
    'INSERT INTO receipts (request_id, log_id, message) VALUES (?, ?, ?)',
    req.params.id, log_id || null, receiptMsg
  );
  // Decrement remaining if not already zero
  if (reqData.remaining > 0) {
    await run('UPDATE requests SET remaining = remaining - 1 WHERE id = ?', req.params.id);
  }
  // If remaining becomes 0, mark as done
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (updated.remaining === 0 && updated.status === 'active') {
    await run('UPDATE requests SET status = "done" WHERE id = ?', req.params.id);
  }
  const receipt = await get('SELECT * FROM receipts WHERE id = ?', result.lastID);
  res.json(receipt);
});

// ─── BLACKLIST ──────────────────────────────────────────────────────
app.get('/api/admin/blacklist', requireAdmin, async (req, res) => {
  const rows = await all(`
    SELECT b.*, u.username as created_by_name FROM blacklist b
    LEFT JOIN users u ON b.created_by = u.id
    ORDER BY b.created_at DESC
  `);
  res.json(rows);
});

app.post('/api/admin/blacklist', requireAdmin, async (req, res) => {
  const { user_id, torn_id, reason } = req.body;
  if (!user_id && !torn_id) {
    return res.status(400).json({ error: 'Either user_id or torn_id required' });
  }
  // Check if already blacklisted
  const existing = await get(
    'SELECT * FROM blacklist WHERE (user_id = ? OR torn_id = ?)',
    user_id || null, torn_id || null
  );
  if (existing) return res.status(400).json({ error: 'User already blacklisted' });

  await run(
    'INSERT INTO blacklist (user_id, torn_id, reason, created_by) VALUES (?, ?, ?, ?)',
    user_id || null, torn_id || null, reason || '', req.user.id
  );
  res.json({ success: true });
});

app.delete('/api/admin/blacklist/:id', requireAdmin, async (req, res) => {
  const result = await run('DELETE FROM blacklist WHERE id = ?', req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

// ─── DISPUTE RESOLVE ──────────────────────────────────────────────
app.put('/api/admin/requests/:id/resolve', requireAdmin, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  // If disputed, revert to previous status (active if remaining > 0 else done)
  const newStatus = reqData.remaining > 0 ? 'active' : 'done';
  await run('UPDATE requests SET status = ?, reported = 0 WHERE id = ?', newStatus, req.params.id);
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  res.json(updated);
});

// ─── Blacklist enforcement ──────────────────────────────────────────
// Inside POST /api/requests (after user auth)
if (buyer_id) {
  const blacklisted = await get('SELECT * FROM blacklist WHERE torn_id = ?', buyer_id);
  if (blacklisted) {
    return res.status(403).json({ error: 'Buyer is blacklisted' });
  }
}

// Inside PUT /api/requests/:id/accept (after request validation)
const blacklisted = await get('SELECT * FROM blacklist WHERE user_id = ?', req.user.id);
if (blacklisted) {
  return res.status(403).json({ error: 'You are blacklisted and cannot accept requests' });
}
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === 'nightmare' && password === 'qwerty') {
    const admin = await get('SELECT * FROM users WHERE torn_id = 0');
    if (!admin) return res.status(500).json({ error: 'Admin user not found' });
    const token = jwt.sign(
      { id: admin.id, role: admin.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    return res.json({ token, user: admin });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

// Get current user
app.get('/api/me', authenticate, async (req, res) => {
  const settings = await get('SELECT * FROM user_settings WHERE user_id = ?', req.user.id);
  res.json({ user: req.user, settings });
});

// Update settings
app.put('/api/settings', authenticate, async (req, res) => {
  const { energy, max_energy, interval, tick_time, full_time, profit, total_hits } = req.body;
  await run(`
    UPDATE user_settings SET
      energy = COALESCE(?, energy),
      max_energy = COALESCE(?, max_energy),
      interval = COALESCE(?, interval),
      tick_time = COALESCE(?, tick_time),
      full_time = COALESCE(?, full_time),
      profit = COALESCE(?, profit),
      total_hits = COALESCE(?, total_hits)
    WHERE user_id = ?
  `, energy, max_energy, interval, tick_time, full_time, profit, total_hits, req.user.id);
  const settings = await get('SELECT * FROM user_settings WHERE user_id = ?', req.user.id);
  res.json(settings);
});

// ─── BARS ──────────────────────────────────────────────────────────
app.get('/api/bars', authenticate, async (req, res) => {
  const user = await get('SELECT api_key FROM users WHERE id = ?', req.user.id);
  if (!user || !user.api_key) {
    return res.status(400).json({ error: 'Torn API key not set' });
  }

  const cacheKey = `bars_${req.user.id}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json(cached);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(
      `https://api.torn.com/v2/user/bars?key=${user.api_key}`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);

    if (!response.ok) {
      return res.status(response.status).json({ error: `Torn API returned ${response.status}` });
    }

    const data = await response.json();
    if (data.error) {
      return res.status(400).json({ error: `Torn API error: ${data.error.error || 'Unknown error'}` });
    }

    const bars = data.bars || {};
    cache.set(cacheKey, bars);
    res.json(bars);
  } catch (error) {
    clearTimeout(timeout);
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'Request timed out' });
    }
    console.error('Bars error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── REQUESTS ──────────────────────────────────────────────────────
app.get('/api/requests', authenticate, async (req, res) => {
  let query = 'SELECT * FROM requests';
  const params = [];
  if (req.user.role !== 'admin') {
    query += ' WHERE user_id = ?';
    params.push(req.user.id);
  }
  query += ' ORDER BY created_at DESC';
  const rows = await all(query, ...params);
  res.json(rows);
});

app.post('/api/requests', authenticate, async (req, res) => {
  const { buyer, buyer_id, loser, price, total } = req.body;
  if (!buyer || !price || !total) {
    return res.status(400).json({ error: 'Buyer, price, and total required' });
  }
  const result = await run(`
    INSERT INTO requests (user_id, buyer, buyer_id, loser, price, total, remaining)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, req.user.id, buyer, buyer_id || null, loser || '', price, total, total);
  const newReq = await get('SELECT * FROM requests WHERE id = ?', result.lastID);
  res.json(newReq);
});

app.put('/api/requests/:id/accept', authenticate, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.status !== 'open') return res.status(400).json({ error: 'Request is not open' });
  if (reqData.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'You can only accept requests from your own account' });
  }
  await run('UPDATE requests SET status = "active", hitter_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', req.user.id, req.params.id);
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  res.json(updated);
});

app.put('/api/requests/:id/complete', authenticate, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.hitter_id !== req.user.id) return res.status(403).json({ error: 'Only the assigned hitter can complete' });
  if (reqData.remaining > 0) return res.status(400).json({ error: 'Verify all hits first' });
  await run('UPDATE requests SET status = "done", updated_at = CURRENT_TIMESTAMP WHERE id = ?', req.params.id);
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  res.json(updated);
});

app.put('/api/requests/:id/paid', authenticate, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.hitter_id !== req.user.id) return res.status(403).json({ error: 'Only the assigned hitter can mark paid' });
  if (reqData.remaining > 0) return res.status(400).json({ error: 'Complete all hits first' });
  await run('UPDATE requests SET status = "paid", paid = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?', req.params.id);
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  res.json(updated);
});

app.post('/api/requests/:id/verify', authenticate, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.hitter_id !== req.user.id) return res.status(403).json({ error: 'Only the assigned hitter can verify' });
  if (reqData.remaining <= 0) return res.status(400).json({ error: 'No remaining hits to verify' });

  const user = await get('SELECT api_key FROM users WHERE id = ?', req.user.id);
  if (!user || !user.api_key) {
    return res.status(400).json({ error: 'Torn API key not set for this user' });
  }

  try {
    const response = await fetch(`https://api.torn.com/v2/user/log?limit=20&key=${user.api_key}`);
    if (!response.ok) throw new Error('Failed to fetch logs');
    const data = await response.json();
    if (data.error) throw new Error(data.error);

    const logs = data.log || [];
    const loserId = reqData.loser;
    let found = null;
    for (const log of logs) {
      if (log.details?.category !== 'Attacking') continue;
      const str = JSON.stringify(log.data || {});
      if (str.includes(loserId)) {
        found = log;
        break;
      }
    }
    if (!found) {
      return res.status(400).json({ error: 'No recent attack found against this loser' });
    }

    const newRemaining = Math.max(0, reqData.remaining - 1);
    const newStatus = newRemaining === 0 ? 'done' : reqData.status;
    await run('UPDATE requests SET remaining = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', newRemaining, newStatus, req.params.id);

    const receiptMsg = `Hit verified against ${reqData.loser} at ${new Date(found.timestamp * 1000).toLocaleString()}. Log ID: ${found.id}`;
    await run('INSERT INTO receipts (request_id, log_id, message) VALUES (?, ?, ?)', req.params.id, found.id, receiptMsg);

    await run('UPDATE user_settings SET profit = profit + ?, total_hits = total_hits + 1 WHERE user_id = ?', reqData.price, req.user.id);

    const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
    const receipts = await all('SELECT * FROM receipts WHERE request_id = ?', req.params.id);
    res.json({ ...updated, receipts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/requests/:id', authenticate, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.status !== 'open' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only admins can delete non-open requests' });
  }
  await run('DELETE FROM requests WHERE id = ?', req.params.id);
  res.json({ success: true });
});

// ─── RECEIPTS ──────────────────────────────────────────────────────
app.get('/api/receipts', authenticate, async (req, res) => {
  let query = `
    SELECT r.*, req.buyer, req.loser FROM receipts r
    JOIN requests req ON r.request_id = req.id
  `;
  const params = [];
  if (req.user.role !== 'admin') {
    query += ' WHERE req.user_id = ?';
    params.push(req.user.id);
  }
  query += ' ORDER BY r.timestamp DESC';
  const rows = await all(query, ...params);
  res.json(rows);
});

app.get('/api/requests/:id/receipts', authenticate, async (req, res) => {
  const rows = await all('SELECT * FROM receipts WHERE request_id = ? ORDER BY timestamp DESC', req.params.id);
  res.json(rows);
});

// ─── HIT LOGS ──────────────────────────────────────────────────────
app.get('/api/hit-logs', authenticate, async (req, res) => {
  const rows = await all(`
    SELECT * FROM hit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20
  `, req.user.id);
  res.json(rows);
});

app.post('/api/hit-logs', authenticate, async (req, res) => {
  const { buyer, loser, price, energy_used } = req.body;
  const result = await run(`
    INSERT INTO hit_logs (user_id, buyer, loser, price, energy_used) VALUES (?, ?, ?, ?, ?)
  `, req.user.id, buyer, loser, price, energy_used || 25);
  const log = await get('SELECT * FROM hit_logs WHERE id = ?', result.lastID);
  res.json(log);
});

// ─── ATTACK LOGS ───────────────────────────────────────────────────
app.post('/api/attack-logs/fetch', authenticate, async (req, res) => {
  const user = await get('SELECT api_key FROM users WHERE id = ?', req.user.id);
  if (!user || !user.api_key) {
    return res.status(400).json({ error: 'Torn API key not set' });
  }
  try {
    const response = await fetch(`https://api.torn.com/v2/user/log?limit=100&key=${user.api_key}`);
    const data = await response.json();
    if (data.error) throw new Error(data.error);
    const logs = data.log || [];
    const attacks = logs.filter(entry => {
      const cat = entry.details?.category || '';
      return cat === 'Attacking' || (entry.details?.title || '').toLowerCase().includes('attack');
    });
    await run('DELETE FROM attack_logs WHERE user_id = ?', req.user.id);
    for (const attack of attacks) {
      await run(
        'INSERT INTO attack_logs (user_id, log_data, timestamp, details) VALUES (?, ?, ?, ?)',
        req.user.id,
        JSON.stringify(attack),
        attack.timestamp,
        JSON.stringify(attack.details || {})
      );
    }
    res.json({ success: true, count: attacks.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/attack-logs', authenticate, async (req, res) => {
  let query = 'SELECT * FROM attack_logs';
  const params = [];
  if (req.user.role !== 'admin') {
    query += ' WHERE user_id = ?';
    params.push(req.user.id);
  }
  query += ' ORDER BY timestamp DESC LIMIT 50';
  const rows = await all(query, ...params);
  const parsed = rows.map(row => ({
    ...row,
    log_data: JSON.parse(row.log_data),
    details: row.details ? JSON.parse(row.details) : {}
  }));
  res.json(parsed);
});

// ─── ADMIN ROUTES ────────────────────────────────────────────────
async function requireAdmin(req, res, next) {
  await authenticate(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin required' });
    }
    next();
  });
}

app.get('/api/users', requireAdmin, async (req, res) => {
  const rows = await all('SELECT id, username, role, torn_id, created_at FROM users');
  res.json(rows);
});

app.get('/api/admin/export', requireAdmin, async (req, res) => {
  const users = await all('SELECT id, username, role, torn_id FROM users');
  const requests = await all('SELECT * FROM requests');
  const receipts = await all('SELECT * FROM receipts');
  const hit_logs = await all('SELECT * FROM hit_logs');
  const attack_logs = await all('SELECT id, user_id, timestamp, details FROM attack_logs');
  const user_settings = await all('SELECT user_id, energy, max_energy, interval, profit, total_hits, current_hitter_id FROM user_settings');
  res.json({ users, requests, receipts, hit_logs, attack_logs, user_settings });
});

app.post('/api/admin/import', requireAdmin, async (req, res) => {
  const { requests, receipts, hit_logs } = req.body;
  if (!requests) return res.status(400).json({ error: 'Missing requests data' });

  try {
    await run('DELETE FROM receipts');
    await run('DELETE FROM hit_logs');
    await run('DELETE FROM requests');

    for (const r of requests) {
      await run(`
        INSERT INTO requests (id, user_id, buyer, buyer_id, loser, price, total, remaining, status, hitter_id, paid, reported, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, r.id, r.user_id, r.buyer, r.buyer_id, r.loser, r.price, r.total, r.remaining, r.status, r.hitter_id, r.paid || 0, r.reported || 0, r.created_at || new Date().toISOString(), r.updated_at || new Date().toISOString());
    }

    if (receipts) {
      for (const r of receipts) {
        await run(`
          INSERT INTO receipts (id, request_id, log_id, message, timestamp)
          VALUES (?, ?, ?, ?, ?)
        `, r.id, r.request_id, r.log_id, r.message, r.timestamp || new Date().toISOString());
      }
    }

    if (hit_logs) {
      for (const h of hit_logs) {
        await run(`
          INSERT INTO hit_logs (id, user_id, buyer, loser, price, energy_used, timestamp)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `, h.id, h.user_id, h.buyer, h.loser, h.price, h.energy_used || 25, h.timestamp || new Date().toISOString());
      }
    }

    res.json({ success: true, imported: requests.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── ERROR HANDLER ────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── STATIC FILES ──────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ─── START ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🔥 Torn Loss Manager Backend running on http://localhost:${PORT}`);
  console.log(`👑 Admin: nightmare / qwerty`);
  console.log(`📁 Database: torn_loss_manager.db`);
});
