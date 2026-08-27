// ─── REPLACE THIS ────────────────────────────────────────────────
// async function authenticateApiKey(req, res, next) { ... }

// ─── WITH THIS ──────────────────────────────────────────────────
async function authenticate(req, res, next) {
  let user = null;
  const apiKey = req.headers['x-api-key'];
  const token = req.headers.authorization?.split(' ')[1];

  if (apiKey) {
    try { user = await get('SELECT * FROM users WHERE api_key = ?', apiKey); } catch (e) {}
  }
  if (!user && token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      user = await get('SELECT * FROM users WHERE id = ?', decoded.id);
    } catch (e) {}
  }
  if (!user) {
    const queryKey = req.query['apiKey'] || req.query['X-API-Key'];
    if (queryKey) user = await get('SELECT * FROM users WHERE api_key = ?', queryKey);
  }
  if (!user) return res.status(401).json({ error: 'Authentication required' });

  req.user = user;
  const settings = await get('SELECT * FROM user_settings WHERE user_id = ?', user.id);
  if (!settings) await run('INSERT INTO user_settings (user_id) VALUES (?)', user.id);
  next();
}

// ─── UPDATE ROUTES ──────────────────────────────────────────────
app.get('/api/requests', authenticate, async (req, res) => { ... });
app.get('/api/receipts', authenticate, async (req, res) => { ... });
app.get('/api/attack-logs', authenticate, async (req, res) => { ... });
// ... and all others
