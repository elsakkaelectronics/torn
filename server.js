const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'torn-loss-manager-secret';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── DATABASE ──────────────────────────────────────────────────────
const db = new sqlite3.Database('torn_loss_manager.db');

// Custom promisified wrappers
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

    // Seed admin user
    const existingAdmin = await get('SELECT id FROM users WHERE torn_id = 0');
    if (!existingAdmin) {
      await run(
        'INSERT INTO users (torn_id, username, role) VALUES (?, ?, ?)',
        0, 'admin', 'admin'
      );
      const admin = await get('SELECT id FROM users WHERE torn_id = 0');
      await run('INSERT INTO user_settings (user_id) VALUES (?)', admin.id);
      console.log('✅ Admin user created (nightmare / qwerty)');
    } else {
      console.log('✅ Admin user already exists');
    }
  } catch (e) {
    console.error('❌ Database init error:', e.message);
    throw e;
  }
}
initDb().catch(console.error);

// ─── MIDDLEWARE ────────────────────────────────────────────────────
async function authenticateApiKey(req, res, next) {
  let apiKey = req.headers['x-api-key'];
  // Accept query param for debugging
  if (!apiKey) {
    apiKey = req.query['apiKey'] || req.query['X-API-Key'];
  }
  if (!apiKey) return res.status(401).json({ error: 'API key required' });

  try {
    let user = await get('SELECT * FROM users WHERE api_key = ?', apiKey);
    if (!user) {
      // Fetch from Torn API
      const response = await fetch(`https://api.torn.com/v2/user/basic?key=${apiKey}`);
      if (!response.ok) throw new Error('Invalid API key');
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      const tornId = data.profile.id;

      let existing = await get('SELECT * FROM users WHERE torn_id = ?', tornId);
      if (!existing) {
        const result = await run(
          'INSERT INTO users (torn_id, api_key, username) VALUES (?, ?, ?)',
          tornId, apiKey, data.profile.name || `User${tornId}`
        );
        await run('INSERT INTO user_settings (user_id) VALUES (?)', result.lastID);
        existing = await get('SELECT * FROM users WHERE id = ?', result.lastID);
      } else {
        await run('UPDATE users SET api_key = ? WHERE id = ?', apiKey, existing.id);
        existing = await get('SELECT * FROM users WHERE id = ?', existing.id);
      }
      user = existing;
    }
    req.user = user;
// Ensure user_settings exists
const settings = await get('SELECT * FROM user_settings WHERE user_id = ?', user.id);
if (!settings) {
  await run('INSERT INTO user_settings (user_id) VALUES (?)', user.id);
}
    next();
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
}

function authenticateJWT(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    get('SELECT * FROM users WHERE id = ?', decoded.id)
      .then(user => {
        if (!user) return res.status(401).json({ error: 'User not found' });
        req.user = user;
        next();
      })
      .catch(() => res.status(401).json({ error: 'Invalid token' }));
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin required' });
  next();
}

// ─── ROUTES ─────────────────────────────────────────────────────────

// Admin login
app.post('api/auth/login', async (req, res) => {
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
app.get('/api/me', authenticateApiKey, async (req, res) => {
  const settings = await get('SELECT * FROM user_settings WHERE user_id = ?', req.user.id);
  res.json({ user: req.user, settings });
});

// Update settings
app.put('/api/settings', authenticateApiKey, async (req, res) => {
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

// ─── BARS (energy, nerve, happy, life, chain) ────────────────────
app.get('/api/bars', authenticateApiKey, async (req, res) => {
  const user = await get('SELECT api_key FROM users WHERE id = ?', req.user.id);
  if (!user || !user.api_key) {
    return res.status(400).json({ error: 'Torn API key not set' });
  }
  try {
    const response = await fetch(`https://api.torn.com/v2/user/bars?key=${user.api_key}`);
    if (!response.ok) throw new Error('Failed to fetch bars');
    const data = await response.json();
    if (data.error) throw new Error(data.error);
    res.json(data.bars || {});
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── REQUESTS ──────────────────────────────────────────────────────
app.get('/api/requests', authenticateApiKey, async (req, res) => {
  const rows = await all('SELECT * FROM requests WHERE user_id = ? ORDER BY created_at DESC', req.user.id);
  res.json(rows);
});

app.post('/api/requests', authenticateApiKey, async (req, res) => {
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

app.put('/api/requests/:id/accept', authenticateApiKey, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.status !== 'open') return res.status(400).json({ error: 'Request is not open' });
  await run('UPDATE requests SET status = "active", hitter_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', req.user.id, req.params.id);
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  res.json(updated);
});

app.put('/api/requests/:id/complete', authenticateApiKey, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.hitter_id !== req.user.id) return res.status(403).json({ error: 'Only the assigned hitter can complete' });
  if (reqData.remaining > 0) return res.status(400).json({ error: 'Verify all hits first' });
  await run('UPDATE requests SET status = "done", updated_at = CURRENT_TIMESTAMP WHERE id = ?', req.params.id);
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  res.json(updated);
});

app.put('/api/requests/:id/paid', authenticateApiKey, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.hitter_id !== req.user.id) return res.status(403).json({ error: 'Only the assigned hitter can mark paid' });
  if (reqData.remaining > 0) return res.status(400).json({ error: 'Complete all hits first' });
  await run('UPDATE requests SET status = "paid", paid = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?', req.params.id);
  const updated = await get('SELECT * FROM requests WHERE id = ?', req.params.id);
  res.json(updated);
});

app.post('/api/requests/:id/verify', authenticateApiKey, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
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

app.delete('/api/requests/:id', authenticateApiKey, async (req, res) => {
  const reqData = await get('SELECT * FROM requests WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
  if (!reqData) return res.status(404).json({ error: 'Request not found' });
  if (reqData.status !== 'open' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only admins can delete non-open requests' });
  }
  await run('DELETE FROM requests WHERE id = ?', req.params.id);
  res.json({ success: true });
});

// ─── RECEIPTS ──────────────────────────────────────────────────────
app.get('/api/receipts', authenticateApiKey, async (req, res) => {
  const rows = await all(`
    SELECT r.*, req.buyer, req.loser FROM receipts r
    JOIN requests req ON r.request_id = req.id
    WHERE req.user_id = ?
    ORDER BY r.timestamp DESC
  `, req.user.id);
  res.json(rows);
});

app.get('/api/requests/:id/receipts', authenticateApiKey, async (req, res) => {
  const rows = await all('SELECT * FROM receipts WHERE request_id = ? ORDER BY timestamp DESC', req.params.id);
  res.json(rows);
});

// ─── HIT LOGS ──────────────────────────────────────────────────────
app.get('/api/hit-logs', authenticateApiKey, async (req, res) => {
  const rows = await all(`
    SELECT * FROM hit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20
  `, req.user.id);
  res.json(rows);
});

app.post('/api/hit-logs', authenticateApiKey, async (req, res) => {
  const { buyer, loser, price, energy_used } = req.body;
  const result = await run(`
    INSERT INTO hit_logs (user_id, buyer, loser, price, energy_used) VALUES (?, ?, ?, ?, ?)
  `, req.user.id, buyer, loser, price, energy_used || 25);
  const log = await get('SELECT * FROM hit_logs WHERE id = ?', result.lastID);
  res.json(log);
});

// ─── ATTACK LOGS ───────────────────────────────────────────────────
app.post('/api/attack-logs/fetch', authenticateApiKey, async (req, res) => {
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

app.get('/api/attack-logs', authenticateApiKey, async (req, res) => {
  const rows = await all(`
    SELECT * FROM attack_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50
  `, req.user.id);
  const parsed = rows.map(row => ({
    ...row,
    log_data: JSON.parse(row.log_data),
    details: row.details ? JSON.parse(row.details) : {}
  }));
  res.json(parsed);
});

// ─── ADMIN ROUTES ────────────────────────────────────────────────
async function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await get('SELECT * FROM users WHERE id = ?', decoded.id);
      if (user && user.role === 'admin') {
        req.user = user;
        return next();
      }
    } catch (e) {}
  }
  await authenticateApiKey(req, res, () => {
    if (req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({ error: 'Admin required' });
    }
  });
}

app.get('/api/users', adminAuth, async (req, res) => {
  const rows = await all('SELECT id, username, role, torn_id, created_at FROM users');
  res.json(rows);
});

app.get('/api/admin/export', adminAuth, async (req, res) => {
  const users = await all('SELECT id, username, role, torn_id FROM users');
  const requests = await all('SELECT * FROM requests');
  const receipts = await all('SELECT * FROM receipts');
  const hit_logs = await all('SELECT * FROM hit_logs');
  const attack_logs = await all('SELECT id, user_id, timestamp, details FROM attack_logs');
  const user_settings = await all('SELECT user_id, energy, max_energy, interval, profit, total_hits, current_hitter_id FROM user_settings');
  res.json({ users, requests, receipts, hit_logs, attack_logs, user_settings });
});

app.post('/api/admin/import', adminAuth, async (req, res) => {
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
