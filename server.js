// Run: npm install && ADMIN_PASSWORD=xxx AUDIT_KEY=yyy npm start   (use behind HTTPS)
const express = require('express'), { DatabaseSync } = require('node:sqlite'), crypto = require('crypto'), path = require('path'), fs = require('fs');  // node:sqlite is built into Node 22: no native build needed
process.on('uncaughtException', e => console.error('FATAL', e)); process.on('unhandledRejection', e => console.error('UNHANDLED', e));
const AUDIT_KEY = process.env.AUDIT_KEY || 'change-me-audit-key';
const H = p => crypto.scryptSync(String(p), 'election-portal-v1', 32), AH = H(process.env.ADMIN_PASSWORD || 'admin123');
const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'portal.db'); fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE); db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;');
db.transaction = fn => (...a) => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(...a); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
db.exec(`
CREATE TABLE IF NOT EXISTS members(id INTEGER PRIMARY KEY,member_id TEXT UNIQUE NOT NULL,name TEXT,mobile TEXT UNIQUE NOT NULL,email TEXT,category TEXT,eligible INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS elections(id INTEGER PRIMARY KEY,code TEXT UNIQUE,name TEXT,post TEXT NOT NULL,start_at TEXT,end_at TEXT,result_at TEXT,live_candidates INTEGER DEFAULT 0,otp_ttl INTEGER DEFAULT 300,max_attempts INTEGER DEFAULT 5,locked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS candidates(id INTEGER PRIMARY KEY,election_id INTEGER REFERENCES elections(id),code TEXT,name TEXT NOT NULL,description TEXT,sort INTEGER DEFAULT 0,active INTEGER DEFAULT 1);
-- Secrecy: participation (WHO voted) and ballots (WHAT was chosen) share no key. Ballots have no member id, no timestamp, no rowid order.
CREATE TABLE IF NOT EXISTS voter_participation(id INTEGER PRIMARY KEY,election_id INTEGER NOT NULL,member_id INTEGER NOT NULL,voted_at TEXT,UNIQUE(election_id,member_id));
CREATE TABLE IF NOT EXISTS ballots(txn_id TEXT PRIMARY KEY,election_id INTEGER NOT NULL,candidate_id INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS otps(mobile TEXT PRIMARY KEY,hash TEXT,expires INTEGER,tries INTEGER DEFAULT 0,sent_at INTEGER,resends INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY,message TEXT,send_at TEXT,sent INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS notification_logs(id INTEGER PRIMARY KEY,notice_id INTEGER,member_id INTEGER,channel TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS uploads(id INTEGER PRIMARY KEY,at TEXT,filename TEXT,imported INTEGER,rejected INTEGER);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,at TEXT DEFAULT CURRENT_TIMESTAMP,actor TEXT,action TEXT,election_id INTEGER,detail TEXT,ip TEXT);
CREATE TRIGGER IF NOT EXISTS al_u BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'audit log is immutable'); END;
CREATE TRIGGER IF NOT EXISTS al_d BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT,'audit log is immutable'); END;
`);
const log = (req, actor, action, eid, detail) => db.prepare('INSERT INTO audit_log(actor,action,election_id,detail,ip) VALUES(?,?,?,?,?)').run(actor, action, eid || null, typeof detail === 'string' ? detail : JSON.stringify(detail || ''), req.ip);
// ---- SMS / email: plug in your provider (MSG91, Twilio, SES, SMTP). Return true on success. ----
const sendSms = async (mobile, text) => { console.log(`[SMS ${mobile}] ${text}`); return true; };
const sendEmail = async (to, subject, text) => { if (!to) return false; console.log(`[EMAIL ${to}] ${subject}: ${text}`); return true; };

const norm = m => String(m || '').replace(/\D/g, '').slice(-10), hash = s => crypto.createHash('sha256').update(s).digest('hex');
const status = e => { const n = Date.now(); if (e.locked) return 'LOCKED'; if (n < Date.parse(e.start_at)) return 'UPCOMING'; if (n <= Date.parse(e.end_at)) return 'OPEN'; return n >= Date.parse(e.result_at || e.end_at) ? 'RESULTS' : 'CLOSED'; };
const hits = new Map(), limit = (n, ms) => (req, res, next) => { const k = req.ip + req.path, now = Date.now(), a = (hits.get(k) || []).filter(t => now - t < ms); a.push(now); hits.set(k, a); a.length > n ? res.status(429).json({ error: 'Too many attempts. Please try again later.' }) : next(); };
const adminTokens = new Set(), sessions = new Map();
const app = express(); app.set('trust proxy', 1); app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:" }); next(); });
app.get('/health', (_, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public')));
const admin = (req, res, next) => adminTokens.has(req.get('x-token')) ? next() : res.status(401).json({ error: 'Please log in as commissioner.' });
const voter = (req, res, next) => { const s = sessions.get(req.get('x-session')); if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Session expired. Please verify your OTP again.' }); req.member = s.member_id; next(); };
const view = e => {
  const st = status(e), eligible = db.prepare('SELECT COUNT(*) c FROM members WHERE eligible=1').get().c, polled = db.prepare('SELECT COUNT(*) c FROM voter_participation WHERE election_id=?').get(e.id).c;
  const cands = db.prepare('SELECT id,code,name,description FROM candidates WHERE election_id=? AND active=1 ORDER BY sort,id').all(e.id);
  const o = { id: e.id, code: e.code, name: e.name, post: e.post, start_at: e.start_at, end_at: e.end_at, result_at: e.result_at || e.end_at, status: st, eligible, polled, turnout: eligible ? +(polled * 100 / eligible).toFixed(1) : 0, candidates: cands, live_candidates: !!e.live_candidates, locked: !!e.locked };
  if (e.live_candidates && st === 'OPEN') o.live = tally(e.id);
  return o;
};
const tally = id => { const r = db.prepare('SELECT c.name,COUNT(b.txn_id) votes FROM candidates c LEFT JOIN ballots b ON b.candidate_id=c.id WHERE c.election_id=? AND c.active=1 GROUP BY c.id ORDER BY votes DESC').all(id), t = r.reduce((a, x) => a + x.votes, 0); return r.map(x => ({ ...x, pct: t ? +(x.votes * 100 / t).toFixed(1) : 0 })); };

// ================= Admin =================
app.post('/api/admin/login', limit(8, 60000), (req, res) => {
  const ok = crypto.timingSafeEqual(H(req.body.password), AH); log(req, 'admin', ok ? 'ADMIN_LOGIN' : 'ADMIN_LOGIN_FAILED');
  if (!ok) return res.status(401).json({ error: 'Wrong password' });
  const t = crypto.randomBytes(24).toString('hex'); adminTokens.add(t); res.json({ token: t });
});
app.get('/api/admin/dashboard', admin, (req, res) => {
  const c = q => db.prepare(q).get().c, els = db.prepare('SELECT * FROM elections ORDER BY id').all().map(view);
  res.json({ members: c('SELECT COUNT(*) c FROM members'), eligible: c('SELECT COUNT(*) c FROM members WHERE eligible=1'), candidates: c('SELECT COUNT(*) c FROM candidates WHERE active=1'), active: els.filter(e => e.status === 'OPEN').length, completed: els.filter(e => ['CLOSED', 'RESULTS'].includes(e.status)).length, votes: c('SELECT COUNT(*) c FROM voter_participation'), elections: els });
});
// Members: dry-run validation first, then import valid rows
app.post('/api/admin/members', admin, (req, res) => {
  const rows = req.body.rows || [], errors = [], seenM = new Set(), seenId = new Set(), good = [];
  rows.forEach((r, i) => {
    const row = i + 2, mob = norm(r.mobile), mid = String(r.member_id || '').trim(), em = String(r.email || '').trim(), bad = [];
    if (!mid) bad.push('Member ID missing'); else if (seenId.has(mid)) bad.push('Duplicate Member ID'); 
    if (mob.length !== 10 || !/^[6-9]/.test(mob)) bad.push('Invalid mobile'); else if (seenM.has(mob)) bad.push('Duplicate mobile');
    if (em && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) bad.push('Invalid email');
    if (bad.length) return errors.push({ row, member_id: mid, msg: bad.join(', ') });
    seenId.add(mid); seenM.add(mob); good.push({ mid, name: r.name || '', mob, em, cat: r.category || '', el: /^(no|0|false|not)/i.test(String(r.eligible || 'yes').trim()) ? 0 : 1 });
  });
  if (!req.body.dry) {
    const up = db.prepare('INSERT INTO members(member_id,name,mobile,email,category,eligible) VALUES(?,?,?,?,?,?) ON CONFLICT(member_id) DO UPDATE SET name=excluded.name,mobile=excluded.mobile,email=excluded.email,category=excluded.category,eligible=excluded.eligible');
    try { db.transaction(() => good.forEach(g => up.run(g.mid, g.name, g.mob, g.em, g.cat, g.el)))(); } catch (e) { return res.status(400).json({ error: 'A mobile number in the file already belongs to another Member ID.' }); }
    db.prepare('INSERT INTO uploads(at,filename,imported,rejected) VALUES(?,?,?,?)').run(new Date().toISOString(), req.body.filename || '', good.length, errors.length);
    log(req, 'admin', 'MEMBER_UPLOAD', null, { imported: good.length, rejected: errors.length });
  }
  res.json({ valid: good.length, errors, imported: !req.body.dry });
});
app.get('/api/admin/members', admin, (req, res) => {
  const q = `%${req.query.q || ''}%`, p = Math.max(0, +req.query.page || 0);
  const rows = db.prepare('SELECT member_id,name,mobile,email,eligible FROM members WHERE member_id LIKE ? OR name LIKE ? OR mobile LIKE ? OR email LIKE ? ORDER BY id LIMIT 20 OFFSET ?').all(q, q, q, q, p * 20).map(m => ({ ...m, mobile: 'XXXXXX' + m.mobile.slice(-4) }));
  res.json({ rows, uploads: db.prepare('SELECT * FROM uploads ORDER BY id DESC LIMIT 5').all() });
});
app.post('/api/admin/elections', admin, (req, res) => {
  const { name, post, start_at, end_at, result_at, candidates } = req.body;
  if (!name || !post || !start_at || !end_at || !(candidates || []).length) return res.status(400).json({ error: 'Name, post, start, end and at least one candidate are required.' });
  if (Date.parse(end_at) <= Date.parse(start_at)) return res.status(400).json({ error: 'End time must be after start time.' });
  const e = db.transaction(() => {
    const id = db.prepare('INSERT INTO elections(name,post,start_at,end_at,result_at) VALUES(?,?,?,?,?)').run(name, post, start_at, end_at, result_at || end_at).lastInsertRowid;
    const code = `${post.replace(/[^A-Za-z0-9]/g, '').toUpperCase()}-${new Date(start_at).getFullYear()}-${String(id).padStart(3, '0')}`;
    db.prepare('UPDATE elections SET code=? WHERE id=?').run(code, id);
    candidates.forEach((c, i) => db.prepare('INSERT INTO candidates(election_id,code,name,description,sort) VALUES(?,?,?,?,?)').run(id, `C${String(i + 1).padStart(3, '0')}`, c.name, c.description || '', i));
    return code;
  })();
  log(req, 'admin', 'ELECTION_CREATED', null, e); res.json({ election_id: e });
});
app.post('/api/admin/elections/:id/candidates', admin, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id); if (!e || status(e) !== 'UPCOMING') return res.status(400).json({ error: 'Candidates can only be changed before voting starts.' });
  const n = db.prepare('SELECT COUNT(*) c FROM candidates WHERE election_id=?').get(e.id).c;
  if (req.body.remove) db.prepare('UPDATE candidates SET active=0 WHERE id=? AND election_id=?').run(req.body.remove, e.id);
  else db.prepare('INSERT INTO candidates(election_id,code,name,description,sort) VALUES(?,?,?,?,?)').run(e.id, `C${String(n + 1).padStart(3, '0')}`, req.body.name, req.body.description || '', n);
  log(req, 'admin', 'CANDIDATE_CHANGED', e.id, req.body); res.json({ ok: true });
});
app.post('/api/admin/elections/:id/settings', admin, (req, res) => {   // extension, live-count toggle, OTP rules, emergency lock
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id); if (!e) return res.status(404).json({ error: 'Not found' });
  const m = { ...e, ...Object.fromEntries(['end_at', 'result_at', 'live_candidates', 'otp_ttl', 'max_attempts', 'locked'].filter(k => k in req.body).map(k => [k, req.body[k]])) };
  db.prepare('UPDATE elections SET end_at=?,result_at=?,live_candidates=?,otp_ttl=?,max_attempts=?,locked=? WHERE id=?').run(m.end_at, m.result_at, m.live_candidates ? 1 : 0, m.otp_ttl, m.max_attempts, m.locked ? 1 : 0, e.id);
  log(req, 'admin', 'ELECTION_CONFIG_CHANGED', e.id, req.body); res.json({ ok: true });
});
app.get('/api/admin/report/:id', admin, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id), v = e && view(e);
  if (!e || !['CLOSED', 'RESULTS'].includes(v.status)) return res.status(403).json({ error: 'Report is available after voting closes.' });
  log(req, 'admin', 'REPORT_DOWNLOAD', e.id);
  const csv = [`Election ID,${e.code}`, `Election,${e.name}`, `Post,${e.post}`, `Eligible,${v.eligible}`, `Polled,${v.polled}`, `Turnout %,${v.turnout}`, '', 'Candidate,Votes,Percentage', ...tally(e.id).map(r => `"${r.name.replace(/"/g, '""')}",${r.votes},${r.pct}`)].join('\n');
  res.type('text/csv').send(csv);
});
app.post('/api/admin/notices', admin, (req, res) => { if (!req.body.message) return res.status(400).json({ error: 'Message required' }); db.prepare('INSERT INTO notices(message,send_at) VALUES(?,?)').run(req.body.message, req.body.send_at || new Date().toISOString()); log(req, 'admin', 'NOTICE_SCHEDULED'); res.json({ ok: true }); });
app.get('/api/admin/notices', admin, (req, res) => res.json(db.prepare(`SELECT n.id,n.message,n.send_at,n.sent,(SELECT COUNT(*) FROM notification_logs WHERE notice_id=n.id AND status='SENT') ok,(SELECT COUNT(*) FROM notification_logs WHERE notice_id=n.id AND status='FAILED') failed FROM notices n ORDER BY id DESC LIMIT 10`).all()));
// Restricted audit mode: key + written reason, always logged. Ballots cannot be linked to voters by design.
app.post('/api/admin/audit', admin, limit(5, 60000), (req, res) => {
  const { key, reason, election_id } = req.body;
  if (key !== AUDIT_KEY) { log(req, 'admin', 'RESTRICTED_AUDIT_DENIED', election_id, reason); return res.status(403).json({ error: 'Invalid audit key.' }); }
  if (!reason || reason.trim().length < 10) return res.status(400).json({ error: 'Please give a written reason (at least 10 characters).' });
  log(req, 'admin', 'RESTRICTED_AUDIT_ACCESS', election_id, reason);
  res.json({ participation: db.prepare('SELECT m.member_id,m.name,p.voted_at FROM voter_participation p JOIN members m ON m.id=p.member_id WHERE p.election_id=?').all(election_id), log: db.prepare('SELECT at,actor,action,detail,ip FROM audit_log WHERE election_id=? ORDER BY id DESC LIMIT 100').all(election_id) });
});

// ================= Public =================
app.get('/api/public', (_, res) => res.json({ elections: db.prepare('SELECT * FROM elections ORDER BY id').all().map(view) }));
app.get('/api/results/:id', (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id), v = e && view(e);
  if (!e || v.status !== 'RESULTS') return res.status(403).json({ error: 'Results are not published yet.' });
  res.json({ ...v, results: tally(e.id) });
});

// ================= OTP + voting =================
const cfg = () => db.prepare('SELECT * FROM elections').all().find(e => status(e) === 'OPEN') || { otp_ttl: 300, max_attempts: 5 };
app.post('/api/otp/request', limit(6, 600000), async (req, res) => {
  const mobile = norm(req.body.mobile), m = db.prepare('SELECT * FROM members WHERE mobile=? AND eligible=1').get(mobile);
  if (!m) { log(req, 'member', 'OTP_REJECTED_NOT_ELIGIBLE', null, 'XXXXXX' + mobile.slice(-4)); return res.status(403).json({ error: 'Mobile number is not registered for this election.' }); }
  const els = db.prepare('SELECT * FROM elections').all().map(status);
  if (!els.includes('OPEN')) return res.status(400).json({ error: els.includes('UPCOMING') ? 'Voting has not started yet.' : 'Voting has ended.' });
  const o = db.prepare('SELECT * FROM otps WHERE mobile=?').get(mobile);
  if (o && Date.now() - o.sent_at < 30000) return res.status(429).json({ error: 'Please wait 30 seconds before requesting another OTP.' });
  if (o && o.resends >= 5 && Date.now() - o.sent_at < 3600000) return res.status(429).json({ error: 'Too many OTP requests. Please try again later.' });
  const otp = String(crypto.randomInt(100000, 1000000));
  db.prepare('INSERT OR REPLACE INTO otps(mobile,hash,expires,tries,sent_at,resends) VALUES(?,?,?,0,?,?)').run(mobile, hash(otp), Date.now() + cfg().otp_ttl * 1000, Date.now(), (o?.resends || 0) + 1);
  await sendSms(mobile, `Your election OTP is ${otp}. Valid for ${Math.round(cfg().otp_ttl / 60)} minutes. Do not share it.`);
  log(req, 'member:' + m.member_id, 'OTP_GENERATED'); res.json({ ok: true });
});
app.post('/api/otp/verify', limit(15, 600000), (req, res) => {
  const mobile = norm(req.body.mobile), o = db.prepare('SELECT * FROM otps WHERE mobile=?').get(mobile), m = db.prepare('SELECT * FROM members WHERE mobile=? AND eligible=1').get(mobile);
  if (!o || !m) return res.status(400).json({ error: 'Please request an OTP first.' });
  if (o.tries >= cfg().max_attempts) return res.status(429).json({ error: 'Too many OTP attempts. Please try again later.' });
  if (o.expires < Date.now()) return res.status(400).json({ error: 'OTP has expired. Please request a new OTP.' });
  const good = crypto.timingSafeEqual(Buffer.from(hash(String(req.body.otp))), Buffer.from(o.hash));
  log(req, 'member:' + m.member_id, good ? 'OTP_VERIFIED' : 'OTP_FAILED');
  if (!good) { db.prepare('UPDATE otps SET tries=tries+1 WHERE mobile=?').run(mobile); return res.status(400).json({ error: 'Incorrect OTP. Please try again.' }); }
  db.prepare('DELETE FROM otps WHERE mobile=?').run(mobile);
  const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, { member_id: m.id, exp: Date.now() + 15 * 60000 }); res.json({ session: t, name: m.name });
});
app.get('/api/ballot', voter, (req, res) => res.json({ elections: db.prepare('SELECT * FROM elections').all().map(view).filter(e => e.status === 'OPEN').map(e => ({ ...e, voted: !!db.prepare('SELECT 1 FROM voter_participation WHERE election_id=? AND member_id=?').get(e.id, req.member) })) }));
app.post('/api/vote', voter, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.body.election_id);
  if (!e || status(e) !== 'OPEN') return res.status(400).json({ error: status(e || { start_at: 0, end_at: 0 }) === 'UPCOMING' ? 'Voting has not started yet.' : 'Voting has ended.' });
  if (!db.prepare('SELECT 1 FROM candidates WHERE id=? AND election_id=? AND active=1').get(req.body.candidate_id, e.id)) return res.status(400).json({ error: 'Invalid candidate.' });
  const txn = 'TX-' + crypto.randomBytes(8).toString('hex').toUpperCase();
  try {
    db.transaction(() => {   // both rows succeed or neither; UNIQUE(election_id,member_id) blocks races
      db.prepare('INSERT INTO voter_participation(election_id,member_id,voted_at) VALUES(?,?,?)').run(e.id, req.member, new Date().toISOString());
      db.prepare('INSERT INTO ballots(txn_id,election_id,candidate_id) VALUES(?,?,?)').run(txn, e.id, req.body.candidate_id);
    })();
    log(req, 'member', 'VOTE_RECORDED', e.id, 'ok'); res.json({ ok: true, txn });
  } catch (err) { log(req, 'member', 'DUPLICATE_VOTE_ATTEMPT', e.id); res.status(409).json({ error: 'You have already cast your vote for this election. You cannot vote again.' }); }
});

setInterval(async () => {
  for (const n of db.prepare('SELECT * FROM notices WHERE sent=0 AND send_at<=?').all(new Date().toISOString())) {
    db.prepare('UPDATE notices SET sent=1 WHERE id=?').run(n.id);
    for (const m of db.prepare('SELECT * FROM members WHERE eligible=1').all()) {
      const ok = await sendSms(m.mobile, n.message).catch(() => false); db.prepare('INSERT INTO notification_logs(notice_id,member_id,channel,status) VALUES(?,?,?,?)').run(n.id, m.id, 'SMS', ok ? 'SENT' : 'FAILED');
      if (m.email) { const k = await sendEmail(m.email, 'Election notice', n.message).catch(() => false); db.prepare('INSERT INTO notification_logs(notice_id,member_id,channel,status) VALUES(?,?,?,?)').run(n.id, m.id, 'EMAIL', k ? 'SENT' : 'FAILED'); }
    }
  }
}, 60000);
app.listen(process.env.PORT || 3000, () => console.log('Election portal listening on', process.env.PORT || 3000, 'db:', DB_FILE));
