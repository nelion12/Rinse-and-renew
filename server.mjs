import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const DATA = join(ROOT, 'data');
mkdirSync(DATA, { recursive: true });
const db = new DatabaseSync(join(DATA, 'rinse-renew.sqlite'));
db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','staff')),
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id),
    service TEXT NOT NULL CHECK (service IN ('Wash & fold','Carpet refresh','Shoe care','Garment care')),
    pickup_date TEXT NOT NULL,
    pickup_area TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pickup requested' CHECK (status IN ('Pickup requested','Pickup scheduled','Received','Checked in','Cleaning','Ready for delivery','Out for delivery','Completed','Cancelled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS orders_user_idx ON orders(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS order_items (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    customer_condition TEXT NOT NULL DEFAULT '',
    intake_condition TEXT NOT NULL DEFAULT '',
    condition_updated_at TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS order_items_order_idx ON order_items(order_id);
`);

const MAX_BODY = 64 * 1024;
const SESSION_DAYS = 7;
const SERVICE_NAMES = new Set(['Wash & fold','Carpet refresh','Shoe care','Garment care']);
const ORDER_STATUSES = new Set(['Pickup requested','Pickup scheduled','Received','Checked in','Cleaning','Ready for delivery','Out for delivery','Completed','Cancelled']);
const failedLogins = new Map();

function json(res, status, payload, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(JSON.stringify(payload));
}
function fail(res, status, error) { json(res, status, { error }); }
function now() { return new Date().toISOString(); }
function tokenDigest(token) { return createHash('sha256').update(token).digest('hex'); }
function safeUser(user) { return { id: user.id, name: user.name, email: user.email, role: user.role }; }
function cookieMap(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const i = part.indexOf('='); return [part.slice(0, i), decodeURIComponent(part.slice(i + 1))];
  }));
}
function cookieHeader(value, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `rr_session=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}
function currentUser(req) {
  const token = cookieMap(req).rr_session;
  if (!token) return null;
  const row = db.prepare(`SELECT u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(tokenDigest(token), now());
  return row || null;
}
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
async function readBody(req) {
  let size = 0; const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error('Request body is too large'), { status: 413 });
    chunks.push(chunk);
  }
  if (!size) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('Send a valid JSON request body'), { status: 400 }); }
}
function rateLimited(req) {
  const ip = req.socket.remoteAddress || 'unknown';
  const t = Date.now(); const recent = (failedLogins.get(ip) || []).filter(at => t - at < 15 * 60 * 1000);
  if (recent.length >= 10) return true;
  recent.push(t); failedLogins.set(ip, recent); return false;
}
function passwordHash(password, salt = randomBytes(16).toString('hex')) {
  return `scrypt$${salt}$${scryptSync(password, salt, 64).toString('hex')}`;
}
function passwordMatches(password, saved) {
  const [scheme, salt, hash] = (saved || '').split('$');
  if (scheme !== 'scrypt' || !salt || !hash) return false;
  const actual = scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
function createSession(userId) {
  const token = randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400_000).toISOString();
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(tokenDigest(token), userId, expires);
  return token;
}
function getOrder(orderId) {
  const order = db.prepare('SELECT id,public_id,user_id,service,pickup_date,pickup_area,status,created_at,updated_at FROM orders WHERE id=? OR public_id=?').get(orderId, orderId);
  if (!order) return null;
  order.items = db.prepare('SELECT id,description,customer_condition,intake_condition,condition_updated_at FROM order_items WHERE order_id=? ORDER BY created_at,id').all(order.id);
  delete order.user_id;
  return order;
}
function makePublicId() { return `RR-${randomBytes(3).toString('hex').toUpperCase()}`; }
function parseItems(value) {
  if (typeof value !== 'string') throw Object.assign(new Error('Add at least one item or item group'), { status: 400 });
  const lines = value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  if (!lines.length || lines.length > 25) throw Object.assign(new Error('Enter between 1 and 25 items, one per line'), { status: 400 });
  return lines.map(line => {
    if (line.length > 500) throw Object.assign(new Error('Keep each item description under 500 characters'), { status: 400 });
    const parts = line.split(/\s+(?:—|–|\|)\s+/, 2);
    return { description: parts[0].trim(), customer_condition: (parts[1] || '').trim() };
  });
}
function limitInput(value, name, max) {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > max) throw Object.assign(new Error(`${name} is required and must be under ${max} characters`), { status: 400 });
  return value.trim();
}
function serveStatic(req, res, pathname) {
  let path = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.slice(1));
  path = normalize(path).replace(/^([.][.][/\\])+/, '');
  const file = join(ROOT, path);
  if (!file.startsWith(ROOT)) return fail(res, 403, 'Forbidden');
  try {
    const body = readFileSync(file);
    const type = ({ '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp' })[extname(file)] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'strict-origin-when-cross-origin' }); res.end(body);
  } catch { fail(res, 404, 'Not found'); }
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const route = url.pathname;
  if (route.startsWith('/api/') && req.method !== 'GET' && !originAllowed(req)) return fail(res, 403, 'Request origin is not allowed');

  if (route === '/api/health' && req.method === 'GET') return json(res, 200, { status: 'ok' });
  if (route === '/api/auth/register' && req.method === 'POST') {
    const body = await readBody(req);
    const name = limitInput(body.name, 'Name', 100);
    const email = limitInput(body.email, 'Email', 254).toLowerCase();
    const password = body.password;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Enter a valid email address');
    if (typeof password !== 'string' || password.length < 10 || password.length > 200) return fail(res, 400, 'Password must be between 10 and 200 characters');
    const id = randomUUID();
    try { db.prepare('INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?)').run(id,name,email,passwordHash(password),now()); }
    catch (e) { if (String(e.message).includes('UNIQUE')) return fail(res, 409, 'An account with that email already exists'); throw e; }
    const token = createSession(id); const user = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(id);
    return json(res, 201, { user: safeUser(user) }, { 'Set-Cookie': cookieHeader(token, SESSION_DAYS * 86400) });
  }
  if (route === '/api/auth/login' && req.method === 'POST') {
    if (rateLimited(req)) return fail(res, 429, 'Too many sign-in attempts. Try again later.');
    const body = await readBody(req);
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const user = db.prepare('SELECT id,name,email,role,password_hash FROM users WHERE email=?').get(email);
    if (!user || !passwordMatches(password,user.password_hash)) return fail(res, 401, 'Email or password is incorrect');
    const token = createSession(user.id); delete user.password_hash;
    return json(res, 200, { user: safeUser(user) }, { 'Set-Cookie': cookieHeader(token, SESSION_DAYS * 86400) });
  }
  if (route === '/api/auth/logout' && req.method === 'POST') {
    const token = cookieMap(req).rr_session;
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenDigest(token));
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
  }
  if (route === '/api/auth/me' && req.method === 'GET') {
    const user = currentUser(req);
    if (!user) return fail(res, 401, 'Sign in to continue');
    return json(res, 200, { user: safeUser(user) });
  }
  if (route === '/api/orders' && req.method === 'POST') {
    const user = currentUser(req); if (!user) return fail(res, 401, 'Create an account or sign in to book a pickup');
    const body = await readBody(req);
    if (!SERVICE_NAMES.has(body.service)) return fail(res, 400, 'Choose a valid service');
    const date = limitInput(body.pickup_date, 'Pickup date', 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(`${date}T00:00:00Z`)) || date < new Date().toISOString().slice(0,10)) return fail(res, 400, 'Choose a valid pickup date');
    const area = limitInput(body.pickup_area, 'Pickup area', 160);
    const items = parseItems(body.items);
    const orderId = randomUUID(); let publicId = makePublicId();
    while (db.prepare('SELECT 1 FROM orders WHERE public_id=?').get(publicId)) publicId = makePublicId();
    const stamp = now();
    const insertOrder = db.prepare('INSERT INTO orders(id,public_id,user_id,service,pickup_date,pickup_area,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)');
    const insertItem = db.prepare('INSERT INTO order_items(id,order_id,description,customer_condition,created_at) VALUES(?,?,?,?,?)');
    db.exec('BEGIN');
    try { insertOrder.run(orderId,publicId,user.id,body.service,date,area,'Pickup requested',stamp,stamp); for (const item of items) insertItem.run(randomUUID(),orderId,item.description,item.customer_condition,stamp); db.exec('COMMIT'); }
    catch (error) { db.exec('ROLLBACK'); throw error; }
    return json(res, 201, { order: getOrder(orderId) });
  }
  if (route === '/api/orders' && req.method === 'GET') {
    const user = currentUser(req); if (!user) return fail(res, 401, 'Sign in to view orders');
    const rows = db.prepare('SELECT id,public_id FROM orders WHERE user_id=? ORDER BY created_at DESC').all(user.id);
    return json(res, 200, { orders: rows.map(row => getOrder(row.id)) });
  }
  const staffMatch = route.match(/^\/api\/staff\/orders\/([^/]+)$/);
  if (staffMatch && req.method === 'PATCH') {
    const user = currentUser(req); if (!user) return fail(res, 401, 'Sign in required'); if (user.role !== 'staff') return fail(res, 403, 'Staff access required');
    const body = await readBody(req); const order = db.prepare('SELECT id FROM orders WHERE id=? OR public_id=?').get(staffMatch[1],staffMatch[1]);
    if (!order) return fail(res, 404, 'Order not found');
    if (body.status !== undefined) {
      if (!ORDER_STATUSES.has(body.status)) return fail(res, 400, 'Choose a valid order status');
      db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run(body.status,now(),order.id);
    }
    if (body.item_conditions !== undefined) {
      if (!Array.isArray(body.item_conditions) || body.item_conditions.length > 25) return fail(res, 400, 'Send a valid list of item condition updates');
      const update = db.prepare('UPDATE order_items SET intake_condition=?,condition_updated_at=? WHERE id=? AND order_id=?');
      for (const item of body.item_conditions) {
        const note = limitInput(item.intake_condition, 'Condition note', 500);
        const result = update.run(note,now(),item.id,order.id);
        if (!result.changes) return fail(res, 400, 'An item does not belong to this order');
      }
      db.prepare('UPDATE orders SET updated_at=? WHERE id=?').run(now(),order.id);
    }
    return json(res, 200, { order: getOrder(order.id) });
  }

  if (route.startsWith('/api/')) return fail(res, 404, 'API route not found');
  if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 405, 'Method not allowed');
  serveStatic(req,res,route);
}

if (process.argv[2] === 'promote-staff') {
  const email = process.argv[3]?.trim().toLowerCase();
  if (!email) { console.error('Usage: node server.mjs promote-staff <existing-customer-email>'); process.exit(2); }
  const result = db.prepare("UPDATE users SET role='staff' WHERE email=?").run(email);
  if (!result.changes) { console.error('No account found for that email. Create the account first.'); process.exit(1); }
  console.log(`Staff access enabled for ${email}`);
  process.exit(0);
}

const server = createServer((req,res) => {
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  handle(req,res).catch(error => {
    if (!res.headersSent) fail(res,error.status || 500,error.status ? error.message : 'Server error');
    else res.destroy();
    if (!error.status) console.error(error);
  });
});
const port = Number(process.env.PORT || 3000);
server.listen(port, process.env.HOST || '127.0.0.1', () => console.log(`Rinse & Renew running at http://${process.env.HOST || '127.0.0.1'}:${port}`));

