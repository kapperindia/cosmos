// Run: npm install && ADMIN_PASSWORD=xxx AUDIT_KEY=yyy npm start   (use behind HTTPS)
const express = require('express'), { DatabaseSync } = require('node:sqlite'), crypto = require('crypto'), path = require('path'), fs = require('fs');  // node:sqlite is built into Node 22: no native build needed
// Public (non-secret) COSMEX settings, so only the passwords need to be set in Hostinger. Hostinger environment variables, if set, override these.
process.env.FIREBASE_PROJECT_ID ||= 'cosmex-e9ba2';
process.env.FIREBASE_API_KEY ||= 'AIzaSyCSkPhbd6G7Eik_MoMrpsv9rxYsWdZXMpk';   // Firebase web API keys are public identifiers, not secrets
process.env.FIREBASE_AUTH_DOMAIN ||= 'cosmex-e9ba2.firebaseapp.com';
process.env.FIREBASE_DATABASE_URL ||= 'https://cosmex-e9ba2-default-rtdb.firebaseio.com';
process.env.ORG_NAME ||= 'COSMEX';
process.on('uncaughtException', e => console.error('FATAL', e)); process.on('unhandledRejection', e => console.error('UNHANDLED', e));
const AUDIT_KEY = process.env.AUDIT_KEY || 'change-me-audit-key';
const H = p => crypto.scryptSync(String(p), 'election-portal-v1', 32), AH = H(process.env.ADMIN_PASSWORD || 'admin123');
const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'portal.db'); fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
// ---- Durability: if the host wiped the database file on redeploy, restore the latest snapshot from Supabase Storage BEFORE opening it ----
(function restoreIfNeeded() {
  const url = (process.env.SUPABASE_URL || '').replace(/\/$/, ''), key = process.env.SUPABASE_SERVICE_KEY;
  if (!url || !key) return;
  try {
    let needs = !fs.existsSync(DB_FILE) || fs.statSync(DB_FILE).size === 0;
    if (!needs) { // a freshly created, still-empty database also counts as "wiped"
      try { const t = new DatabaseSync(DB_FILE); const n = t.prepare("SELECT (SELECT COUNT(*) FROM sqlite_master WHERE name IN ('members','elections')) t").get().t;
        needs = n < 2 || (t.prepare('SELECT COUNT(*) c FROM members').get().c === 0 && t.prepare('SELECT COUNT(*) c FROM elections').get().c === 0); t.close(); } catch (e) { needs = true; }
    }
    if (!needs) return;
    const code = `fetch(process.env.U+'/storage/v1/object/backups/portal-latest.db',{headers:{apikey:process.env.K,Authorization:'Bearer '+process.env.K}}).then(async r=>{if(!r.ok)process.exit(2);require('fs').writeFileSync(process.env.T,Buffer.from(await r.arrayBuffer()))}).catch(()=>process.exit(3))`;
    const tmp = DB_FILE + '.restore';
    require('child_process').execFileSync(process.execPath, ['-e', code], { env: { ...process.env, U: url, K: key, T: tmp }, timeout: 60000 });
    if (fs.readFileSync(tmp).subarray(0, 15).toString() !== 'SQLite format 3') throw new Error('downloaded backup is not a valid database');
    for (const x of ['', '-wal', '-shm']) fs.rmSync(DB_FILE + x, { force: true });
    fs.renameSync(tmp, DB_FILE); console.log('RESTORED database from Supabase backup');
  } catch (e) { console.log('No backup restored:', e.status === 2 ? 'no backup exists yet' : e.message); }
})();
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
CREATE TRIGGER IF NOT EXISTS ba_u BEFORE UPDATE ON ballots BEGIN SELECT RAISE(ABORT,'ballots are permanent and cannot be modified'); END;
CREATE TRIGGER IF NOT EXISTS ba_d BEFORE DELETE ON ballots BEGIN SELECT RAISE(ABORT,'ballots are permanent and cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS vp_u BEFORE UPDATE ON voter_participation BEGIN SELECT RAISE(ABORT,'voter records are permanent and cannot be modified'); END;
CREATE TRIGGER IF NOT EXISTS vp_d BEFORE DELETE ON voter_participation BEGIN SELECT RAISE(ABORT,'voter records are permanent and cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS nl_u BEFORE UPDATE ON notification_logs BEGIN SELECT RAISE(ABORT,'notification logs are permanent and cannot be modified'); END;
CREATE TRIGGER IF NOT EXISTS nl_d BEFORE DELETE ON notification_logs BEGIN SELECT RAISE(ABORT,'notification logs are permanent and cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS up_u BEFORE UPDATE ON uploads BEGIN SELECT RAISE(ABORT,'upload history are permanent and cannot be modified'); END;
CREATE TRIGGER IF NOT EXISTS up_d BEFORE DELETE ON uploads BEGIN SELECT RAISE(ABORT,'upload history are permanent and cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS el_d BEFORE DELETE ON elections BEGIN SELECT RAISE(ABORT,'elections cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS ca_d BEFORE DELETE ON candidates BEGIN SELECT RAISE(ABORT,'candidates cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS me_d BEFORE DELETE ON members WHEN EXISTS(SELECT 1 FROM voter_participation WHERE member_id=OLD.id) BEGIN SELECT RAISE(ABORT,'a member who has voted cannot be deleted'); END;
`);
try { db.exec('ALTER TABLE audit_log ADD COLUMN hash TEXT'); } catch (e) { /* column already exists */ }
const chainHash = (prev, r) => crypto.createHash('sha256').update([prev, r.at, r.actor, r.action, r.election_id ?? '', r.detail ?? '', r.ip ?? ''].join('|')).digest('hex');
// Every audit entry carries a hash of itself + the previous entry's hash, so any later tampering breaks the chain and is detectable
const log = (req, actor, action, eid, detail) => {
  const r = { at: new Date().toISOString(), actor, action, election_id: eid || null, detail: typeof detail === 'string' ? detail : JSON.stringify(detail || ''), ip: String(req.ip || '') };
  const prev = db.prepare('SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1').get()?.hash || '';
  db.prepare('INSERT INTO audit_log(at,actor,action,election_id,detail,ip,hash) VALUES(?,?,?,?,?,?,?)').run(r.at, r.actor, r.action, r.election_id, r.detail, r.ip, chainHash(prev, r));
};
// ---- SMS / email: plug in your provider (MSG91, Twilio, SES, SMTP). Return true on success. ----
const sendSms = async (mobile, text) => { console.log(`[SMS ${mobile}] ${text}`); return true; };
const sendEmail = async (to, subject, text) => { if (!to) return false; console.log(`[EMAIL ${to}] ${subject}: ${text}`); return true; };

const norm = m => String(m || '').replace(/\D/g, '').slice(-10), hash = s => crypto.createHash('sha256').update(s).digest('hex');
const status = e => { const n = Date.now(); if (e.locked) return 'LOCKED'; if (n < Date.parse(e.start_at)) return 'UPCOMING'; if (n <= Date.parse(e.end_at)) return 'OPEN'; return n >= Date.parse(e.result_at || e.end_at) ? 'RESULTS' : 'CLOSED'; };
const hits = new Map(), limit = (n, ms) => (req, res, next) => { const k = req.ip + req.path, now = Date.now(), a = (hits.get(k) || []).filter(t => now - t < ms); a.push(now); hits.set(k, a); a.length > n ? res.status(429).json({ error: 'Too many attempts. Please try again later.' }) : next(); };
try { db.exec('ALTER TABLE voter_participation ADD COLUMN via TEXT'); } catch (e) { /* already there */ }
try { db.exec('ALTER TABLE candidates ADD COLUMN photo TEXT'); } catch (e) { /* already there */ }
const adminTokens = new Set(), sessions = new Map();
const app = express(); app.set('trust proxy', 1); app.use(express.json({ limit: '80mb' }));
// Mark the database "changed" after any successful write so the background job backs it up
app.use((req, res, next) => { const t0 = process.hrtime.bigint(); res.on('finish', () => { const ms = Number(process.hrtime.bigint() - t0) / 1e6; if (ms > 700 && req.path.startsWith('/api/')) console.warn(`SLOW ${Math.round(ms)}ms ${req.method} ${req.path}`); }); next(); });
let dirty = false; app.use((req, res, next) => { if (req.method !== 'GET' && req.path.startsWith('/api/')) res.on('finish', () => { if (res.statusCode < 400) dirty = true; }); next(); });

// Content-Security-Policy. When Firebase sign-in is configured, only Google's Firebase/reCAPTCHA hosts are additionally allowed.
const fbConfig = () => process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_API_KEY ? { apiKey: process.env.FIREBASE_API_KEY, authDomain: process.env.FIREBASE_AUTH_DOMAIN || process.env.FIREBASE_PROJECT_ID + '.firebaseapp.com', projectId: process.env.FIREBASE_PROJECT_ID, cc: process.env.FIREBASE_COUNTRY_CODE || '91' } : null;
const CSP = fbConfig()
  ? `default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.google.com https://apis.google.com; img-src 'self' data: https://www.gstatic.com https://www.google.com; frame-src https://www.google.com https://recaptcha.google.com https://${fbConfig().authDomain}; connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com https://firebaseinstallations.googleapis.com https://www.google.com`
  : "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:";
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': CSP }); next(); });
app.get('/health', (_, res) => res.send('ok'));
// Public privacy policy page (good practice). Set ORG_NAME and CONTACT_EMAIL in the host's environment variables.
const escH = x => String(x).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
app.get(['/privacy', '/privacy-policy'], (req, res) => {
  const org = escH(process.env.ORG_NAME || 'COSMEX'), mail = escH(process.env.CONTACT_EMAIL || 'the Election Commissioner'), upd = '12 October 2026';
  res.type('html').send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Privacy Policy - ${org} Online Election Portal</title>
<style>body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;background:#f4f6fb;color:#14213d;line-height:1.6}main{max-width:780px;margin:0 auto;padding:24px 18px 60px}h1{font-size:30px;margin:8px 0}h2{font-size:20px;margin:28px 0 6px}a{color:#0b2a6f}.top{background:#0e1a4a;color:#fff;padding:14px 18px}.top a{color:#fff;text-decoration:none;font-weight:700}li{margin:4px 0}.mut{color:#5b6679}@media(prefers-color-scheme:dark){body{background:#0f1424;color:#eef1fa}a{color:#8fb0ff}.mut{color:#9aa6bf}}</style></head><body>
<div class="top"><a href="/">&larr; ${org} Online Election Portal</a></div><main>
<h1>Privacy Policy</h1><p class="mut">Last updated: ${upd}</p>
<p>This policy explains how the ${org} Online Election Portal ("the portal") collects, uses and protects personal information when registered members vote in elections run by ${org} ("we", "the association").</p>
<h2>1. Information we collect</h2><ul>
<li><b>Member register details</b> supplied by the association: member ID, name, mobile number, email address (if provided) and category.</li>
<li><b>Voting records:</b> whether you have voted in each election and when. Your choice of candidate is stored separately (see section 4).</li>
<li><b>Verification data:</b> a one-time password (stored only in scrambled form and deleted after use or expiry), or the phone number verified through Firebase when you choose SMS verification.</li>
<li><b>Security logs:</b> actions taken on the portal (for example OTP requests, votes cast, commissioner actions) with the time and IP address, to detect misuse.</li></ul>
<h2>2. How we use it</h2><ul>
<li>To confirm you are a registered member and are allowed to vote.</li>
<li>To send you a one-time password by SMS (including through Google Firebase phone verification), and to send election notices.</li>
<li>To make sure each member votes only once, to count votes, to show turnout and results, and to give the Election Commissioner voter and yet-to-vote lists.</li>
<li>To keep election records that can be checked later if a question is raised.</li></ul>
<p>We do not sell your information, use it for advertising, or share it for marketing.</p>
<h2>3. Secrecy of your vote</h2>
<p>The portal records <i>that</i> you voted separately from <i>what</i> you chose. Ballots carry no member ID or time, so a vote cannot be linked back to a voter, not even by the Election Commissioner. Candidate-wise counts are shown only as the election rules allow.</p>
<h2>4. Who can see your information</h2><ul>
<li>The Election Commissioner and authorised officials can see the member register and the voted / yet-to-vote lists.</li>
<li>Our service providers who run the portal: the web host, the SMS provider, and the cloud services used for the member database and backups (Google Firebase and Supabase). They handle data only to provide these services.</li>
<li>Authorities, where the law requires it.</li></ul>
<h2>5. Storage, security and retention</h2>
<p>Data is stored on secured servers and in private cloud storage. Access to commissioner functions needs a password. Backups are kept so records survive system changes. Because the association's elections must be verifiable, voting records, the audit log and uploaded member files are kept permanently and cannot be edited or deleted. Other member details are kept while you remain a member and as long as needed for the association's records.</p>
<h2>6. Cookies and tracking</h2>
<p>The portal does not use advertising cookies or third-party trackers.</p>
<h2>7. Your choices and rights</h2>
<p>You may ask to see the information we hold about you, to correct wrong details (such as your mobile number or email), or to ask questions about how it is used. Election records already created cannot be erased, as explained above. Contact us at the address below.</p>
<h2>8. Children</h2><p>The portal is for adult members of the association and is not intended for children.</p>
<h2>9. Changes to this policy</h2><p>If we change this policy, the new version will be posted on this page with a new date.</p>
<h2>10. Contact</h2><p>For privacy questions or requests, contact: <b>${mail}</b> (${org} Election Commissioner).</p>
</main></body></html>`);
});

// Works whether index.html sits in ./public/ or in the repo root (only index.html is ever served from the root, never server.js or the database)
const BUILD = '2026-10-14c-live-speed';
const PUB = path.join(__dirname, 'public'), CANDS = [path.join(PUB, 'index.html'), path.join(__dirname, 'index.html')].filter(f => fs.existsSync(f)).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs), HOME = CANDS[0];  // if two copies exist, the newest one wins
const sendHome = (_, res) => HOME ? res.sendFile(HOME, { headers: { 'Cache-Control': 'no-cache' } }) : res.status(500).send('index.html not found. Place it in the public/ folder.');
app.get(['/', '/index.html'], sendHome);
if (fs.existsSync(PUB)) app.use(express.static(PUB, { index: false }));
app.get('/version', (_, res) => res.json({ build: BUILD, page_served_from: HOME ? path.relative(__dirname, HOME) : null, page_modified: HOME ? fs.statSync(HOME).mtime.toISOString() : null }));
const admin = (req, res, next) => adminTokens.has(req.get('x-token')) ? next() : res.status(401).json({ error: 'Please log in as commissioner.' });
const voter = (req, res, next) => { const s = sessions.get(req.get('x-session')); if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Session expired. Please verify your OTP again.' }); req.member = s.member_id; req.via = s.via || 'otp'; next(); };
const view = e => {
  const st = status(e), eligible = db.prepare('SELECT COUNT(*) c FROM members WHERE eligible=1').get().c, polled = db.prepare('SELECT COUNT(*) c FROM voter_participation WHERE election_id=?').get(e.id).c;
  const cands = db.prepare("SELECT id,code,name,description,(photo IS NOT NULL AND photo<>'') has_photo,LENGTH(photo) plen FROM candidates WHERE election_id=? AND active=1 ORDER BY sort,id").all(e.id).map((c, i) => ({ id: c.id, code: c.code, serial: i + 1, name: c.name, description: c.description, photo: c.has_photo ? `/api/cphoto/${c.id}?v=${c.plen}` : null }));
  const o = { id: e.id, code: e.code, name: e.name, post: e.post, start_at: e.start_at, end_at: e.end_at, result_at: e.result_at || e.end_at, status: st, eligible, polled, turnout: eligible ? +(polled * 100 / eligible).toFixed(1) : 0, candidates: cands, live_candidates: !!e.live_candidates, locked: !!e.locked };
  if (e.live_candidates && st === 'OPEN') o.live = tally(e.id);
  return o;
};
const tally = id => { const r = db.prepare('SELECT c.name,COUNT(b.txn_id) votes FROM candidates c LEFT JOIN ballots b ON b.candidate_id=c.id WHERE c.election_id=? AND c.active=1 GROUP BY c.id ORDER BY votes DESC').all(id), t = r.reduce((a, x) => a + x.votes, 0); return r.map(x => ({ ...x, pct: t ? +(x.votes * 100 / t).toFixed(1) : 0 })); };

// ================= Admin =================
// ---- Commissioner OTP login. Authorised numbers live in the "commissioners" table; the primary number can never be removed. ----
db.exec('CREATE TABLE IF NOT EXISTS commissioners(id INTEGER PRIMARY KEY, mobile TEXT UNIQUE NOT NULL, name TEXT, is_primary INTEGER DEFAULT 0, added_at TEXT, added_by TEXT)');
const PRIMARY_COMM = String(process.env.COMMISSIONER_MOBILE || '9430375773').replace(/\D/g, '').slice(-10);
db.prepare('INSERT OR IGNORE INTO commissioners(mobile,name,is_primary,added_at,added_by) VALUES(?,?,1,?,?)').run(PRIMARY_COMM, 'Chief Commissioner', new Date().toISOString(), 'system');
const adminWho = new Map(), getComm = m => db.prepare('SELECT * FROM commissioners WHERE mobile=?').get(m);
const issueAdmin = (req, mobile, how) => { const t = crypto.randomBytes(24).toString('hex'); adminTokens.add(t); adminWho.set(t, mobile); log(req, 'admin', 'ADMIN_LOGIN_' + how, null, 'XXXXXX' + mobile.slice(-4)); return t; };
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });   // never let the browser keep API answers (ballot, lists) for the Back button
app.post('/api/admin/logout', admin, (req, res) => { const t = req.get('x-token'); adminTokens.delete(t); adminWho.delete(t); res.json({ ok: true }); });
// ---- Changeable commissioner password (stored as a salted hash; replaces the ADMIN_PASSWORD value once changed) ----
db.exec('CREATE TABLE IF NOT EXISTS admin_auth(id INTEGER PRIMARY KEY CHECK(id=1), salt TEXT, hash TEXT, updated_at TEXT, updated_by TEXT)');
const pwCheck = p => { const r = db.prepare('SELECT * FROM admin_auth WHERE id=1').get(); return r ? crypto.timingSafeEqual(crypto.scryptSync(String(p), r.salt, 32), Buffer.from(r.hash, 'hex')) : crypto.timingSafeEqual(H(p), AH); };
app.post('/api/admin/password', limit(8, 600000), admin, (req, res) => {
  const tok = req.get('x-token'), viaOtp = adminWho.has(tok), np = String(req.body.new_password || ''), cur = String(req.body.current_password || '');
  if (!viaOtp && !pwCheck(cur)) { log(req, 'admin', 'ADMIN_PASSWORD_CHANGE_FAILED'); return res.status(403).json({ error: 'The current password is not correct.' }); }
  if (np.length < 8 || !/[A-Za-z]/.test(np) || !/\d/.test(np)) return res.status(400).json({ error: 'The new password needs at least 8 characters, with letters and numbers.' });
  if (!viaOtp && np === cur) return res.status(400).json({ error: 'The new password must be different from the current one.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO admin_auth(id,salt,hash,updated_at,updated_by) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET salt=excluded.salt,hash=excluded.hash,updated_at=excluded.updated_at,updated_by=excluded.updated_by').run(salt, crypto.scryptSync(np, salt, 32).toString('hex'), new Date().toISOString(), viaOtp ? 'XXXXXX' + adminWho.get(tok).slice(-4) : 'password login');
  for (const t of [...adminTokens]) if (t !== tok && !adminWho.has(t)) adminTokens.delete(t);   // other password sessions are signed out
  log(req, 'admin', 'ADMIN_PASSWORD_CHANGED'); res.json({ ok: true });
});
// ---- Temporary OTP: the commissioner issues a one-time code for a member whose OTP is not arriving ----
db.exec('CREATE TABLE IF NOT EXISTS temp_otps(id INTEGER PRIMARY KEY, mobile TEXT NOT NULL, member_id TEXT, hash TEXT NOT NULL, created_at TEXT, expires INTEGER, created_by TEXT, tries INTEGER DEFAULT 0, used_at TEXT, revoked INTEGER DEFAULT 0)');
const tmpHash = (code, mobile) => crypto.createHash('sha256').update(code + ':' + mobile).digest('hex');
app.post('/api/admin/temp-otp', admin, async (req, res) => {
  const mobile = norm(req.body.mobile), m = await findMember(mobile);
  if (!m) return res.status(404).json({ error: 'This mobile number is not a registered, eligible member.' });
  const ops = openStatus(m);
  if (!ops.length) return res.status(400).json({ error: 'There is no election open for voting right now.' });
  if (ops.every(e => e.voted)) return res.status(400).json({ error: 'This member has already voted. Voting is allowed only once.' });
  const mins = [5, 10, 30].includes(+req.body.minutes) ? +req.body.minutes : 10, code = String(crypto.randomInt(100000, 1000000)), who = adminWho.get(req.get('x-token')), by = who ? 'XXXXXX' + who.slice(-4) : 'password login';
  db.prepare('UPDATE temp_otps SET revoked=1 WHERE mobile=? AND used_at IS NULL AND revoked=0').run(mobile);
  db.prepare('INSERT INTO temp_otps(mobile,member_id,hash,created_at,expires,created_by) VALUES(?,?,?,?,?,?)').run(mobile, m.member_id, tmpHash(code, mobile), new Date().toISOString(), Date.now() + mins * 60000, by);
  log(req, 'admin', 'TEMP_OTP_ISSUED', null, { mobile: 'XXXXXX' + mobile.slice(-4), minutes: mins, by });
  res.json({ code, name: m.name, member_id: m.member_id, mobile, minutes: mins, expires_at: new Date(Date.now() + mins * 60000).toISOString() });
});
app.get('/api/admin/temp-otps', admin, (req, res) => res.json({ rows: db.prepare('SELECT t.id,t.mobile,t.member_id,t.created_at,t.expires,t.created_by,t.used_at,t.revoked,m.name FROM temp_otps t LEFT JOIN members m ON m.member_id=t.member_id ORDER BY t.id DESC LIMIT 50').all().map(r => ({ ...r, status: r.used_at ? 'Used' : r.revoked ? 'Cancelled' : r.expires < Date.now() ? 'Expired' : 'Active' })) }));
app.post('/api/admin/temp-otp/cancel', admin, (req, res) => { db.prepare('UPDATE temp_otps SET revoked=1 WHERE id=? AND used_at IS NULL').run(+req.body.id || 0); log(req, 'admin', 'TEMP_OTP_CANCELLED'); res.json({ ok: true }); });
app.post('/api/otp/temp-verify', limit(10, 600000), async (req, res) => {
  const mobile = norm(req.body.mobile), code = String(req.body.code || '').trim(), bad = () => res.status(401).json({ error: 'That code is not correct or has expired. Ask the Commissioner for a new one.' });
  const row = db.prepare('SELECT * FROM temp_otps WHERE mobile=? AND used_at IS NULL AND revoked=0 ORDER BY id DESC LIMIT 1').get(mobile);
  if (!row || row.expires < Date.now() || row.tries >= 5) return bad();
  db.prepare('UPDATE temp_otps SET tries=tries+1 WHERE id=?').run(row.id);
  if (!crypto.timingSafeEqual(Buffer.from(tmpHash(code, mobile)), Buffer.from(row.hash))) { log(req, 'member', 'TEMP_OTP_WRONG', null, 'XXXXXX' + mobile.slice(-4)); return bad(); }
  const m = await findMember(mobile); if (!m) return bad();
  const ops = openStatus(m); if (!ops.length || ops.every(e => e.voted)) return res.status(400).json({ error: 'You have already voted, or no election is open.' });
  db.prepare('UPDATE temp_otps SET used_at=? WHERE id=?').run(new Date().toISOString(), row.id);
  const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, { member_id: m.id, exp: Date.now() + 15 * 60000, via: 'temp-otp' });
  log(req, 'member:' + m.member_id, 'TEMP_OTP_USED'); res.json({ session: t, name: m.name });
});
app.get('/api/admin/login-info', (req, res) => res.json({ password: process.env.ADMIN_PASSWORD_LOGIN !== 'off' }));
app.post('/api/admin/otp/options', limit(10, 600000), (req, res) => {
  const m = norm(req.body.mobile), c = getComm(m);
  if (!c) { log(req, 'admin', 'ADMIN_OTP_REJECTED', null, 'XXXXXX' + m.slice(-4)); return res.status(403).json({ error: 'This mobile number is not authorised for commissioner login.' }); }
  res.json({ name: c.name || 'Commissioner', firebase: !!fbConfig(), fbcfg: fbConfig() });
});
app.post('/api/admin/login-firebase', limit(10, 600000), async (req, res) => {   // Firebase SMS OTP
  if (!fbConfig()) return res.status(503).json({ error: 'Firebase sign-in is not set up.' });
  try {
    const pl = await verifyFirebaseToken(req.body.idToken), m = norm(req.body.mobile), tid = crypto.createHash('sha256').update(String(req.body.idToken)).digest('hex');
    if (fbUsed.has(tid)) throw new Error('already used');
    if (pl.firebase?.sign_in_provider !== 'phone' || !pl.phone_number || last10(pl.phone_number) !== m) throw new Error('number mismatch');
    if (!getComm(m)) { log(req, 'admin', 'ADMIN_OTP_REJECTED', null, 'XXXXXX' + m.slice(-4)); return res.status(403).json({ error: 'This mobile number is not authorised for commissioner login.' }); }
    fbUsed.set(tid, Date.now() + 600000); res.json({ token: issueAdmin(req, m, 'FIREBASE') });
  } catch (e) { log(req, 'admin', 'ADMIN_LOGIN_FAILED', null, String(e.message).slice(0, 60)); res.status(401).json({ error: 'Could not verify your phone number. Please try again.' }); }
});
// Managing who can log in (commissioners only)
app.get('/api/admin/commissioners', admin, (req, res) => res.json({ rows: db.prepare('SELECT mobile,name,is_primary,added_at,added_by FROM commissioners ORDER BY is_primary DESC, id').all(), you: adminWho.get(req.get('x-token')) || null }));
app.post('/api/admin/commissioners/add', admin, (req, res) => {
  const m = norm(req.body.mobile), name = String(req.body.name || '').trim();
  if (m.length !== 10 || !/^[6-9]/.test(m)) return res.status(400).json({ error: 'Enter a valid 10-digit mobile number.' });
  if (!name) return res.status(400).json({ error: 'Please enter the name of the person.' });
  if (getComm(m)) return res.status(400).json({ error: 'This number already has commissioner access.' });
  db.prepare('INSERT INTO commissioners(mobile,name,is_primary,added_at,added_by) VALUES(?,?,0,?,?)').run(m, name, new Date().toISOString(), adminWho.get(req.get('x-token')) || 'password login');
  log(req, 'admin', 'COMMISSIONER_ADDED', null, 'XXXXXX' + m.slice(-4)); res.json({ ok: true });
});
app.post('/api/admin/commissioners/remove', admin, (req, res) => {
  const m = norm(req.body.mobile), c = getComm(m);
  if (!c) return res.status(404).json({ error: 'Number not found.' });
  if (c.is_primary) return res.status(400).json({ error: 'The primary commissioner cannot be removed.' });
  if (adminWho.get(req.get('x-token')) === m) return res.status(400).json({ error: 'You cannot remove your own number while logged in with it.' });
  db.prepare('DELETE FROM commissioners WHERE mobile=?').run(m);
  for (const [t, who] of adminWho) if (who === m) { adminTokens.delete(t); adminWho.delete(t); }
  log(req, 'admin', 'COMMISSIONER_REMOVED', null, 'XXXXXX' + m.slice(-4)); res.json({ ok: true });
});
app.post('/api/admin/login', limit(8, 60000), (req, res) => {
  if (process.env.ADMIN_PASSWORD_LOGIN === 'off') return res.status(403).json({ error: 'Password login is turned off. Please log in with an OTP.' });
  const ok = pwCheck(req.body.password); log(req, 'admin', ok ? 'ADMIN_LOGIN' : 'ADMIN_LOGIN_FAILED');
  if (!ok) return res.status(401).json({ error: 'Wrong password' });
  const t = crypto.randomBytes(24).toString('hex'); adminTokens.add(t); res.json({ token: t });
});
app.get('/api/admin/dashboard', admin, (req, res) => {
  const c = q => db.prepare(q).get().c, els = db.prepare('SELECT * FROM elections ORDER BY id').all().map(view);
  res.json({ members: c('SELECT COUNT(*) c FROM members'), eligible: c('SELECT COUNT(*) c FROM members WHERE eligible=1'), candidates: c('SELECT COUNT(*) c FROM candidates WHERE active=1'), active: els.filter(e => e.status === 'OPEN').length, completed: els.filter(e => ['CLOSED', 'RESULTS'].includes(e.status)).length, votes: c('SELECT COUNT(*) c FROM voter_participation'), elections: els });
});

// ---- Firebase Realtime Database: the uploaded member data lives at /members/<member ID> (member ID is the key). SQLite keeps a working copy for voting records. ----
// Env: FIREBASE_DATABASE_URL + (FIREBASE_SERVICE_ACCOUNT = service-account JSON  OR  FIREBASE_DB_SECRET = legacy database secret)
const rtdbReady = () => !!(process.env.FIREBASE_DATABASE_URL && (process.env.FIREBASE_DB_SECRET || process.env.FIREBASE_SERVICE_ACCOUNT));
const fbKey = id => String(id).replace(/[.$#\[\]\/]/g, '_');
let fbTok = { t: '', exp: 0 };
// Accepts the downloaded key file pasted whole, even if the host turned its line breaks into real new lines
function parseServiceAccount(raw) {
  let sa; try { sa = JSON.parse(raw); } catch (e) {
    const em = /"client_email"\s*:\s*"([^"]+)"/.exec(raw || ''), pk = /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/.exec(raw || '');
    if (em && pk) sa = { client_email: em[1], private_key: pk[0].replace(/\\n/g, '\n') };
  }
  if (!sa || !sa.client_email || !sa.private_key) throw new Error('FIREBASE_SERVICE_ACCOUNT in Hostinger is not valid. Paste the entire contents of the downloaded key file, from the first { to the last }.');
  return sa;
}
async function fbAccessToken() {
  if (fbTok.exp > Date.now() + 60000) return fbTok.t;
  const sa = parseServiceAccount(process.env.FIREBASE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000), b = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = b({ alg: 'RS256', typ: 'JWT' }), body = b({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 });
  const jwt = head + '.' + body + '.' + crypto.createSign('RSA-SHA256').update(head + '.' + body).sign(String(sa.private_key).replace(/\\n/g, '\n')).toString('base64url');
  const r = await fetch(process.env.FIREBASE_TOKEN_URL || 'https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt });
  const d = await r.json(); if (!r.ok || !d.access_token) throw new Error('Firebase sign-in failed: ' + (d.error_description || d.error || r.status));
  fbTok = { t: d.access_token, exp: Date.now() + (d.expires_in || 3600) * 1000 }; return fbTok.t;
}
async function rtdb(method, pathq, body, opts = {}) {
  const auth = process.env.FIREBASE_DB_SECRET ? 'auth=' + encodeURIComponent(process.env.FIREBASE_DB_SECRET) : 'access_token=' + await fbAccessToken();
  const r = await fetch(`${process.env.FIREBASE_DATABASE_URL.replace(/\/$/, '')}/${pathq}${pathq.includes('?') ? '&' : '?'}${auth}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(opts.timeout || 20000) });
  const d = await r.json().catch(() => null); if (!r.ok) throw new Error((d && d.error) || 'Firebase database error ' + r.status); return d;
}
const fbVal = (mid, name, mobile, email, category, eligible) => ({ member_id: String(mid), name: name || '', mobile, email: email || '', category: category || '', eligible: !!eligible, updated_at: new Date().toISOString() });
async function fbPushMany(map) { const keys = Object.keys(map); for (let i = 0; i < keys.length; i += 1000) { const part = {}; for (const k of keys.slice(i, i + 1000)) part[k] = map[k]; await rtdb('PATCH', 'members.json', part); } return keys.length; }
// ---- Reading member records from Firebase. People type or import them in the console in many shapes, so field names are matched loosely. ----
const keyOf = k => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
const pick = (o, names) => { for (const k of Object.keys(o)) if (names.includes(keyOf(k))) { const v = o[k]; if (v !== undefined && v !== null && typeof v !== 'object' && String(v).trim() !== '') return v; } return ''; };
const ID_KEYS = ['memberid', 'empid', 'employeeid', 'empno', 'empcode', 'employeecode', 'membershipno', 'membershipnumber', 'memberno', 'id'],
  MOB_KEYS = ['mobile', 'mobileno', 'mobilenumber', 'phone', 'phoneno', 'phonenumber', 'contact', 'contactno', 'contactnumber', 'cell', 'whatsapp'],
  NAME_KEYS = ['name', 'membername', 'fullname', 'employeename', 'empname'], MAIL_KEYS = ['email', 'emailid', 'emailaddress', 'mail'],
  CAT_KEYS = ['category', 'department', 'dept', 'constituency', 'grade', 'cadre'], ELIG_KEYS = ['eligible', 'iseligible', 'status', 'active'];
const NOT_ELIGIBLE = ['false', 'no', 'n', '0', 'noteligible', 'ineligible', 'inactive', 'disabled', 'blocked', 'removed'];
function readRecord(key, v, useKey) {
  if (!v || typeof v !== 'object') return { error: 'not a member record' };
  const mid = String(pick(v, ID_KEYS) || (useKey ? decodeURIComponent(String(key)) : '')).trim();
  if (!mid) return { error: 'no Member ID' };
  const raw = pick(v, MOB_KEYS); if (raw === '') return { mid, error: 'no mobile number' };
  const digits = String(typeof raw === 'number' ? Math.round(raw) : raw).replace(/\D/g, '');
  if (digits.length < 10) return { mid, error: `mobile number has only ${digits.length} digits` };
  const el = pick(v, ELIG_KEYS);
  return { member_id: mid, mobile: digits.slice(-10), name: String(pick(v, NAME_KEYS)).trim(), email: String(pick(v, MAIL_KEYS)).trim(), category: String(pick(v, CAT_KEYS)).trim(), eligible: NOT_ELIGIBLE.includes(keyOf(el)) ? 0 : 1 };
}
// Copy one record into the local working database. Returns { row, state: 'added' | 'updated' | 'same' | 'error', error }
function saveLocal(r) {
  const ex = db.prepare('SELECT * FROM members WHERE member_id=?').get(r.member_id);
  try {
    if (ex) {
      if (ex.mobile === r.mobile && (ex.name || '') === r.name && (ex.email || '') === r.email && (ex.category || '') === r.category && ex.eligible === r.eligible) return { row: ex, state: 'same' };
      db.prepare('UPDATE members SET name=?,mobile=?,email=?,category=?,eligible=? WHERE id=?').run(r.name, r.mobile, r.email, r.category, r.eligible, ex.id);
      return { row: db.prepare('SELECT * FROM members WHERE id=?').get(ex.id), state: 'updated' };
    }
    db.prepare('INSERT INTO members(member_id,name,mobile,email,category,eligible) VALUES(?,?,?,?,?,?)').run(r.member_id, r.name, r.mobile, r.email, r.category, r.eligible);
    return { row: db.prepare('SELECT * FROM members WHERE member_id=?').get(r.member_id), state: 'added' };
  } catch (e) {
    const o = db.prepare('SELECT member_id FROM members WHERE mobile=? AND member_id<>?').get(r.mobile, r.member_id);
    return { state: 'error', error: o ? `mobile number is already used by member ${o.member_id}` : e.message };
  }
}
// The phone number is checked against the uploaded data in Firebase first; if Firebase has no exact match or is unreachable, the local copy of the list is used
async function findMember(mobile) {
  // Fast path: the member list is kept in step with Firebase every minute, so a voter we already know is answered instantly from this server.
  // (Waiting on Firebase for every voter made the screen lag during a live election.)
  const fresh = fbSyncState.at && Date.now() - Date.parse(fbSyncState.at) < 5 * 60000;
  if (fresh) { const row = db.prepare('SELECT * FROM members WHERE mobile=?').get(mobile); if (row) return row.eligible ? row : null; }
  if (rtdbReady()) {
    try {
      const d = await rtdb('GET', `members.json?orderBy=${encodeURIComponent('"mobile"')}&equalTo=${encodeURIComponent(JSON.stringify(mobile))}`, undefined, { timeout: 3000 }), hit = d && Object.entries(d).find(([, v]) => v);
      if (hit) { const r = readRecord(hit[0], hit[1], true); if (!r.error) { const s = saveLocal(r); if (s.row) return s.row.eligible ? s.row : null; } }
    } catch (e) { console.error('Firebase lookup failed, using local copy:', e.message); }
  }
  return db.prepare('SELECT * FROM members WHERE mobile=? AND eligible=1').get(mobile) || null;
}
// Find where the member list is stored: normally "members", but a differently named top-level item is accepted too
const MEMBER_ROOT = /^(members?|member[_ -]?list|employees?|users?)$/i;
async function memberPath() {
  const direct = await rtdb('GET', 'members.json?shallow=true');
  if (direct && Object.keys(direct).length) return { path: 'members', keys: ['members'] };
  const root = await rtdb('GET', '.json?shallow=true'), keys = Object.keys(root || {}), alt = keys.find(k => MEMBER_ROOT.test(k) && k !== 'members');
  return alt ? { path: alt, keys } : { path: null, keys };
}
const fbSyncState = { at: null, error: null, last: null, running: null, path: 'members' };
async function pullMembers() {
  if (fbSyncState.running) return fbSyncState.running;
  return fbSyncState.running = (async () => {
    try {
      const where = await memberPath(), out = { pulled: 0, added: 0, updated: 0, skipped: 0, problems: [], path: where.path };
      if (!where.path) {
        out.note = where.keys.length ? `No member list was found at "members". Your Firebase database contains: ${where.keys.join(', ')}. Members must be stored under members/<Member ID>.` : 'The Firebase database is empty. Upload a member file, or use "Send all members to Firebase".';
        Object.assign(fbSyncState, { at: new Date().toISOString(), error: null, last: out }); return out;
      }
      const d = await rtdb('GET', where.path + '.json'), isArr = Array.isArray(d), entries = isArr ? d.map((v, i) => [String(i), v]) : Object.entries(d || {}), seen = new Map();
      db.exec('BEGIN');
      try {
        for (const [k, v] of entries) {
          if (v === null || v === undefined) continue;   // empty slots in a list are ignored
          const r = readRecord(k, v, !isArr), label = (r.member_id || r.mid || k);
          if (r.error) { out.skipped++; out.problems.push(`${label}: ${r.error}`); continue; }
          if (seen.has(r.mobile)) { out.skipped++; out.problems.push(`${label}: same mobile number as ${seen.get(r.mobile)} in this list`); continue; }
          seen.set(r.mobile, r.member_id);
          const s = saveLocal(r);
          if (s.state === 'error') { out.skipped++; out.problems.push(`${label}: ${s.error}`); } else { out.pulled++; if (s.state === 'added') out.added++; else if (s.state === 'updated') out.updated++; }
        }
        db.exec('COMMIT');
      } catch (e) { try { db.exec('ROLLBACK'); } catch (x) { /* nothing open */ } throw e; }
      out.problems = out.problems.slice(0, 15); Object.assign(fbSyncState, { at: new Date().toISOString(), error: null, last: out, path: where.path }); return out;
    } catch (e) { fbSyncState.error = e.message; throw e; } finally { fbSyncState.running = null; }
  })();
}
async function pushAllMembers() { const map = {}; for (const m of db.prepare('SELECT * FROM members').all()) map[fbKey(m.member_id)] = fbVal(m.member_id, m.name, m.mobile, m.email, m.category, m.eligible); return { pushed: await fbPushMany(map) }; }
// Voting records in Firebase. votes/<election>/<member ID> = who voted, with all their details (NOT who they voted for).
// ballots/<election>/<transaction> = the choice, with no member ID and no time, so a vote can never be traced back to a person.
const fbQueue = [], fbEnc = encodeURIComponent;
const fbVotePayload = (e, m, at, via) => ({ member_id: m.member_id, name: m.name || '', mobile: m.mobile, email: m.email || '', category: m.category || '', election_code: e.code, election_name: e.name, post: e.post, voted_at: at, verified_by: via || 'unknown' });
async function fbWriteVote(job) { await rtdb('PUT', `votes/${fbEnc(fbKey(job.code))}/${fbEnc(fbKey(job.mid))}.json`, job.p); await rtdb('PUT', `ballots/${fbEnc(fbKey(job.code))}/${fbEnc(job.txn)}.json`, job.b); }
function fbRecordVote(e, m, candId, txn, at, via) {
  if (!rtdbReady() || !m) return;
  const cand = db.prepare('SELECT name FROM candidates WHERE id=?').get(candId), job = { code: e.code, mid: m.member_id, txn, p: fbVotePayload(e, m, at, via), b: { election_code: e.code, candidate_id: candId, candidate_name: cand ? cand.name : '' } };
  fbWriteVote(job).catch(err => { console.error('Firebase vote write failed, will retry:', err.message); fbQueue.push(job); });
}
setInterval(async () => { if (!fbQueue.length || !rtdbReady()) return; for (const job of fbQueue.splice(0)) { try { await fbWriteVote(job); } catch (e) { fbQueue.push(job); } } }, 60000);
async function pushAllVotes() {
  const rows = db.prepare('SELECT p.voted_at, p.via, m.member_id, m.name, m.mobile, m.email, m.category, e.code, e.name AS ename, e.post FROM voter_participation p JOIN members m ON m.id=p.member_id JOIN elections e ON e.id=p.election_id').all(), votes = {}, ballots = {};
  for (const r of rows) (votes[fbKey(r.code)] ||= {})[fbKey(r.member_id)] = fbVotePayload({ code: r.code, name: r.ename, post: r.post }, r, r.voted_at, r.via);
  for (const b of db.prepare('SELECT b.txn_id, b.candidate_id, c.name cname, e.code FROM ballots b JOIN elections e ON e.id=b.election_id LEFT JOIN candidates c ON c.id=b.candidate_id').all()) (ballots[fbKey(b.code)] ||= {})[b.txn_id] = { election_code: b.code, candidate_id: b.candidate_id, candidate_name: b.cname || '' };
  for (const c of Object.keys(votes)) await rtdb('PATCH', `votes/${fbEnc(c)}.json`, votes[c]);
  for (const c of Object.keys(ballots)) await rtdb('PATCH', `ballots/${fbEnc(c)}.json`, ballots[c]);
  return { votes: rows.length, ballots: Object.values(ballots).reduce((n, o) => n + Object.keys(o).length, 0) };
}
async function saveToFirebase(filename, good, rejected) {
  if (!rtdbReady()) return { skipped: 'Firebase database is not configured.' };
  try {
    const map = {}; for (const g of good) map[fbKey(g.mid)] = fbVal(g.mid, g.name, g.mob, g.em, g.cat, g.el);
    const n = await fbPushMany(map), at = new Date().toISOString();
    await rtdb('PUT', `uploads/${Date.now()}.json`, { filename: filename || 'unnamed', uploaded_at: at, rows: n, rejected });
    return { saved: n, uploaded_at: at };
  } catch (e) { return { error: 'Could not save to Firebase: ' + e.message }; }
}
const fbTry = async f => { if (!rtdbReady()) return undefined; try { await f(); return undefined; } catch (e) { console.error('Firebase sync failed:', e.message); return e.message; } };

// ---- Supabase helpers (optional; need SUPABASE_URL + SUPABASE_SERVICE_KEY) ----
const SBU = () => (process.env.SUPABASE_URL || '').replace(/\/$/, ''), SBK = () => process.env.SUPABASE_SERVICE_KEY || '';
const sbHeaders = extra => ({ apikey: SBK(), Authorization: 'Bearer ' + SBK(), ...extra });
async function sbStore(bucket, objPath, buf, type) {
  const r = await fetch(`${SBU()}/storage/v1/object/${bucket}/${objPath.split('/').map(encodeURIComponent).join('/')}`, { method: 'POST', headers: sbHeaders({ 'Content-Type': type || 'application/octet-stream', 'x-upsert': 'true' }), body: buf });
  if (!r.ok) throw new Error('Storage upload failed (' + r.status + ')');
}
// Each member-file upload: rows saved as a new version (same filename => next version, keyed by mobile) + the original file kept in Storage
async function saveToSupabase(filename, rows, rejected, fileB64) {
  if (!SBU() || !SBK()) return { skipped: 'Supabase is not configured.' };
  try {
    const payload = rows.map(g => ({ mobile: g.mob, member_id: g.mid, name: g.name, email: g.em, category: g.cat, eligible: !!g.el }));
    const hash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex'), fname = filename || 'unnamed';
    const r = await fetch(SBU() + '/rest/v1/rpc/save_member_file', { method: 'POST', headers: sbHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ p_filename: fname, p_hash: hash, p_rows: payload, p_rejected: rejected }) });
    const d = await r.json();
    if (!r.ok) return { error: d.message || 'Supabase rejected the upload.' };
    const x = Array.isArray(d) ? d[0] : d; let stored = false;
    if (fileB64) { // original file, e.g. members.xlsx/v2_2026-10-10T04-30-00Z_members.xlsx
      const safe = fname.replace(/[^\w.\-]+/g, '_'), p = `${safe}/v${x.version}_${new Date(x.uploaded_at).toISOString().replace(/[:.]/g, '-')}_${safe}`;
      await sbStore('member-files', p, Buffer.from(fileB64, 'base64'));
      await fetch(`${SBU()}/rest/v1/member_files?id=eq.${x.file_id}`, { method: 'PATCH', headers: sbHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ storage_path: p }) }); stored = true;
    }
    return { version: x.version, uploaded_at: x.uploaded_at, filename: fname, file_stored: stored };
  } catch (e) { return { error: 'Could not save to Supabase: ' + e.message }; }
}
// ---- Database snapshots: a consistent copy of the whole database is uploaded to Supabase Storage after changes, and once a day ----
let backing = false, lastBackup = null, lastBackupError = null;
async function backupNow(daily) {
  if (!SBU() || !SBK()) return { skipped: true };
  if (backing) return { busy: true }; backing = true;
  try {
    const tmp = DB_FILE + '.snapshot'; fs.rmSync(tmp, { force: true }); db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);
    const buf = fs.readFileSync(tmp); fs.rmSync(tmp, { force: true });
    await sbStore('backups', 'portal-latest.db', buf);
    if (daily) await sbStore('backups', `daily/portal-${new Date().toISOString().slice(0, 10)}.db`, buf);
    dirty = false; lastBackup = new Date().toISOString(); lastBackupError = null; return { ok: true, at: lastBackup };
  } catch (e) { lastBackupError = e.message; console.error('Backup failed:', e.message); return { error: e.message }; } finally { backing = false; }
}
// The snapshot copies the whole database, which briefly freezes the server. While people are voting that would make every screen lag,
// so during a busy period it waits for a quiet moment (no requests for 8 s), takes one at most every 90 s, and never waits longer than 4 min.
let lastReq = 0, lastBackupTry = Date.now();
app.use((req, res, next) => { lastReq = Date.now(); next(); });
setInterval(() => {
  if (!dirty) return; const now = Date.now(), quiet = now - lastReq > 8000, since = now - lastBackupTry;
  if ((quiet && since > 90000) || since > 240000) { lastBackupTry = now; backupNow(false); }
}, 5000);
setInterval(() => backupNow(true), 6 * 3600 * 1000);
setTimeout(() => backupNow(true), 15000);
process.on('SIGTERM', async () => { await backupNow(false); process.exit(0); });
app.post('/api/admin/backup', admin, async (req, res) => res.json(await backupNow(true)));
app.get('/api/admin/backup', admin, (req, res) => res.json({ configured: !!(SBU() && SBK()), last: lastBackup, error: lastBackupError }));
// Members: dry-run validation first, then import valid rows
app.post('/api/admin/members', admin, async (req, res) => {
  const rows = req.body.rows || [], errors = [], seenM = new Set(), seenId = new Set(), good = [], preview = [], exist = new Set(db.prepare('SELECT member_id FROM members').all().map(x => x.member_id));
  rows.forEach((r, i) => {
    const row = i + 2, mob = norm(r.mobile), mid = String(r.member_id || '').trim(), em = String(r.email || '').trim(), bad = [];
    if (!mid) bad.push('Member ID missing'); else if (seenId.has(mid)) bad.push('Duplicate Member ID'); 
    if (mob.length !== 10 || !/^[6-9]/.test(mob)) bad.push('Invalid mobile'); else if (seenM.has(mob)) bad.push('Duplicate mobile');
    if (em && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) bad.push('Invalid email');
    const base = { row, member_id: mid, name: String(r.name || ''), mobile: mob || String(r.mobile || ''), email: em, category: String(r.category || '') };
    if (bad.length) { preview.push({ ...base, status: 'error', msg: bad.join(', ') }); return errors.push({ row, member_id: mid, msg: bad.join(', ') }); }
    preview.push({ ...base, status: exist.has(mid) ? 'update' : 'new' });
    seenId.add(mid); seenM.add(mob); good.push({ mid, name: r.name || '', mob, em, cat: r.category || '', el: /^(no|0|false|not)/i.test(String(r.eligible || 'yes').trim()) ? 0 : 1 });
  });
  if (!req.body.dry) {
    const up = db.prepare('INSERT INTO members(member_id,name,mobile,email,category,eligible) VALUES(?,?,?,?,?,?) ON CONFLICT(member_id) DO UPDATE SET name=excluded.name,mobile=excluded.mobile,email=excluded.email,category=excluded.category,eligible=excluded.eligible');
    try { db.transaction(() => good.forEach(g => up.run(g.mid, g.name, g.mob, g.em, g.cat, g.el)))(); } catch (e) { return res.status(400).json({ error: 'A mobile number in the file already belongs to another Member ID.' }); }
    db.prepare('INSERT INTO uploads(at,filename,imported,rejected) VALUES(?,?,?,?)').run(new Date().toISOString(), req.body.filename || '', good.length, errors.length);
    log(req, 'admin', 'MEMBER_UPLOAD', null, { imported: good.length, rejected: errors.length });
  }
  const saved = req.body.dry ? undefined : await saveToSupabase(req.body.filename, good, errors.length, req.body.file_b64);
  const firebase = req.body.dry ? undefined : await saveToFirebase(req.body.filename, good, errors.length);
  res.json({ valid: good.length, errors, added: preview.filter(x => x.status === 'new').length, updated: preview.filter(x => x.status === 'update').length, preview: req.body.dry ? preview : undefined, imported: !req.body.dry, saved, firebase });
});
app.post('/api/admin/members/add', admin, async (req, res) => {
  const mid = String(req.body.member_id || '').trim(), mob = norm(req.body.mobile), em = String(req.body.email || '').trim();
  if (!mid) return res.status(400).json({ error: 'Member ID is required.' });
  if (mob.length !== 10 || !/^[6-9]/.test(mob)) return res.status(400).json({ error: 'Enter a valid 10-digit mobile number.' });
  if (em && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.status(400).json({ error: 'Invalid email address.' });
  if (db.prepare('SELECT 1 FROM members WHERE member_id=?').get(mid)) return res.status(400).json({ error: 'This Member ID already exists.' });
  if (db.prepare('SELECT 1 FROM members WHERE mobile=?').get(mob)) return res.status(400).json({ error: 'This mobile number already belongs to another member.' });
  db.prepare('INSERT INTO members(member_id,name,mobile,email,category,eligible) VALUES(?,?,?,?,?,1)').run(mid, String(req.body.name || '').trim(), mob, em, String(req.body.category || '').trim());
  log(req, 'admin', 'MEMBER_ADD', null, { member_id: mid });
  const fb_error = await fbTry(() => rtdb('PUT', `members/${encodeURIComponent(fbKey(mid))}.json`, fbVal(mid, String(req.body.name || '').trim(), mob, em, String(req.body.category || '').trim(), 1)));
  res.json({ ok: true, fb_error });
});
app.post('/api/admin/members/remove', admin, async (req, res) => {
  const mid = String(req.body.member_id || '').trim(), m = db.prepare('SELECT * FROM members WHERE member_id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'Member not found.' });
  if (db.prepare('SELECT 1 FROM voter_participation WHERE member_id=?').get(m.id))
    return res.status(400).json({ error: 'This member has already voted, so the record must be kept for the audit trail. Mark the member as not eligible instead.' });
  db.prepare('DELETE FROM otps WHERE mobile=?').run(m.mobile);
  db.prepare('DELETE FROM members WHERE id=?').run(m.id);
  log(req, 'admin', 'MEMBER_REMOVE', null, { member_id: mid });
  const fb_error = await fbTry(() => rtdb('DELETE', `members/${encodeURIComponent(fbKey(mid))}.json`));
  res.json({ ok: true, fb_error });
});
app.post('/api/admin/members/eligible', admin, async (req, res) => {
  const mid = String(req.body.member_id || '').trim(), v = req.body.eligible ? 1 : 0;
  if (!db.prepare('UPDATE members SET eligible=? WHERE member_id=? RETURNING id').get(v, mid)) return res.status(404).json({ error: 'Member not found.' });
  log(req, 'admin', v ? 'MEMBER_ELIGIBLE' : 'MEMBER_INELIGIBLE', null, { member_id: mid });
  const fb_error = await fbTry(() => rtdb('PATCH', `members/${encodeURIComponent(fbKey(mid))}.json`, { eligible: !!v, updated_at: new Date().toISOString() }));
  res.json({ ok: true, fb_error });
});
app.get('/api/admin/members', admin, (req, res) => {
  const q = `%${req.query.q || ''}%`, p = Math.max(0, +req.query.page || 0);
  const rows = db.prepare('SELECT member_id,name,mobile,email,eligible FROM members WHERE member_id LIKE ? OR name LIKE ? OR mobile LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT 20000').all(q, q, q, q);
  res.json({ rows, total: db.prepare('SELECT COUNT(*) c FROM members WHERE member_id LIKE ? OR name LIKE ? OR mobile LIKE ? OR email LIKE ?').get(q, q, q, q).c, uploads: db.prepare('SELECT * FROM uploads ORDER BY id DESC LIMIT 5').all() });
});
app.post('/api/admin/elections', admin, (req, res) => {
  const { name, post, start_at, end_at, result_at, candidates } = req.body;
  if (!name || !post || !start_at || !end_at || !(candidates || []).length || candidates.some(c => !String(c.name || '').trim())) return res.status(400).json({ error: 'Name, post, start, end and at least one candidate are required.' });
  if (Date.parse(end_at) <= Date.parse(start_at)) return res.status(400).json({ error: 'End time must be after start time.' });
  if (candidates.some(c => c.photo && !okPhoto(c.photo))) return res.status(400).json({ error: 'Each photo must be a JPG, PNG or WEBP image under about 600 KB.' });
  const e = db.transaction(() => {
    const id = db.prepare('INSERT INTO elections(name,post,start_at,end_at,result_at) VALUES(?,?,?,?,?)').run(name, post, start_at, end_at, result_at || end_at).lastInsertRowid;
    const code = `${post.replace(/[^A-Za-z0-9]/g, '').toUpperCase()}-${new Date(start_at).getFullYear()}-${String(id).padStart(3, '0')}`;
    db.prepare('UPDATE elections SET code=? WHERE id=?').run(code, id);
    candidates.forEach((c, i) => db.prepare('INSERT INTO candidates(election_id,code,name,description,sort,photo) VALUES(?,?,?,?,?,?)').run(id, `C${String(i + 1).padStart(3, '0')}`, String(c.name).trim(), c.description || '', i, c.photo || null));
    return code;
  })();
  log(req, 'admin', 'ELECTION_CREATED', null, e); res.json({ election_id: e });
});
const okPhoto = p => typeof p === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p) && p.length <= 900000;
app.get('/api/cphoto/:id', (req, res) => {   // candidate photo, shown to voters on the ballot
  const r = db.prepare('SELECT photo FROM candidates WHERE id=? AND active=1').get(+req.params.id);
  const m = r && r.photo && /^data:(image\/[a-z]+);base64,(.*)$/s.exec(r.photo); if (!m) return res.status(404).end();
  res.set({ 'Content-Type': m[1], 'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff' }); res.send(Buffer.from(m[2], 'base64'));
});
app.post('/api/admin/elections/:id/candidates', admin, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id); if (!e || status(e) !== 'UPCOMING') return res.status(400).json({ error: 'Candidates, photos and their order can only be changed before voting starts.' });
  const B = req.body, active = () => db.prepare('SELECT id FROM candidates WHERE election_id=? AND active=1 ORDER BY sort,id').all(e.id).map(x => x.id);
  const renumber = ids => ids.forEach((id, i) => db.prepare('UPDATE candidates SET sort=? WHERE id=?').run(i, id));
  const mine = id => db.prepare('SELECT id FROM candidates WHERE id=? AND election_id=? AND active=1').get(id, e.id);
  if (B.photo != null && B.photo !== '' && !okPhoto(B.photo)) return res.status(400).json({ error: 'Photo must be a JPG, PNG or WEBP image under about 600 KB.' });
  let what = 'ADD';
  if (B.remove) { what = 'REMOVE'; db.prepare('UPDATE candidates SET active=0 WHERE id=? AND election_id=?').run(B.remove, e.id); renumber(active()); }
  else if (B.move) {   // move one place up or down in the serial order
    what = 'MOVE'; const ids = active(), i = ids.indexOf(+B.candidate_id), j = i + (B.move === 'up' ? -1 : 1);
    if (i < 0 || j < 0 || j >= ids.length) return res.status(400).json({ error: 'Cannot move further.' });
    [ids[i], ids[j]] = [ids[j], ids[i]]; renumber(ids);
  } else if (B.set_serial) {   // jump straight to a serial number
    what = 'SERIAL'; const ids = active(), i = ids.indexOf(+B.candidate_id); if (i < 0) return res.status(400).json({ error: 'Candidate not found.' });
    const to = Math.min(Math.max(parseInt(B.set_serial, 10) || 1, 1), ids.length) - 1; ids.splice(to, 0, ids.splice(i, 1)[0]); renumber(ids);
  } else if (B.candidate_id) {   // set or clear the photo of an existing candidate
    what = B.photo ? 'PHOTO' : 'PHOTO_CLEARED'; if (!mine(B.candidate_id)) return res.status(400).json({ error: 'Candidate not found.' });
    db.prepare('UPDATE candidates SET photo=? WHERE id=?').run(B.photo || null, B.candidate_id);
  } else {
    if (!String(B.name || '').trim()) return res.status(400).json({ error: 'Candidate name is required.' });
    const n = db.prepare('SELECT COUNT(*) c FROM candidates WHERE election_id=?').get(e.id).c, k = active().length;
    const id = db.prepare('INSERT INTO candidates(election_id,code,name,description,sort,photo) VALUES(?,?,?,?,?,?)').run(e.id, `C${String(n + 1).padStart(3, '0')}`, String(B.name).trim(), B.description || '', k, B.photo || null).lastInsertRowid;
    if (B.serial) { const ids = active(), i = ids.indexOf(+id); ids.splice(Math.min(Math.max(parseInt(B.serial, 10) || 1, 1), ids.length) - 1, 0, ids.splice(i, 1)[0]); renumber(ids); }
  }
  log(req, 'admin', 'CANDIDATE_' + what, e.id, { candidate_id: B.candidate_id || B.remove || null, name: B.name || null, move: B.move || null, serial: B.set_serial || B.serial || null, photo: B.photo ? 'yes' : null });
  res.json({ ok: true });
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
// Voted / yet-to-vote lists (who participated, never whom they voted for)
app.get('/api/admin/firebase', admin, async (req, res) => {
  if (!rtdbReady()) return res.json({ configured: false });
  try {
    const w = await memberPath(), keys = w.path ? Object.keys(await rtdb('GET', w.path + '.json?shallow=true') || {}) : [], have = new Set(keys), mine = db.prepare('SELECT member_id FROM members').all();
    res.json({ configured: true, in_firebase: keys.length, local: mine.length, only_local: mine.filter(m => !have.has(fbKey(m.member_id)) && !have.has(m.member_id)).length, path: w.path, others: w.path ? [] : w.keys, last_sync: fbSyncState.at, last_error: fbSyncState.error, last: fbSyncState.last });
  } catch (e) { res.json({ configured: true, error: e.message }); }
});
// Called by the Members screen when it opens and every few seconds while it stays open; skips the work if a sync just ran
let lastAuto = 0;
app.post('/api/admin/firebase/sync', admin, async (req, res) => {
  if (!rtdbReady()) return res.json({ configured: false });
  if (Date.now() - lastAuto < 8000 && !req.body.force) return res.json({ configured: true, throttled: true, changed: 0 });
  lastAuto = Date.now();
  try { const r = await pullMembers(); res.json({ configured: true, changed: r.added + r.updated, ...r }); } catch (e) { res.status(502).json({ error: 'Could not read the member list from Firebase: ' + e.message }); }
});
app.post('/api/admin/firebase/push', admin, async (req, res) => { if (!rtdbReady()) return res.status(400).json({ error: 'Firebase is not connected yet. In Hostinger add FIREBASE_SERVICE_ACCOUNT (or FIREBASE_DB_SECRET) and restart the app.' }); try { const r = await pushAllMembers(); log(req, 'admin', 'FIREBASE_PUSH', null, r); res.json({ ok: true, ...r }); } catch (e) { res.status(502).json({ error: e.message }); } });
app.post('/api/admin/firebase/push-votes', admin, async (req, res) => { if (!rtdbReady()) return res.status(400).json({ error: 'Firebase is not connected yet. In Hostinger add FIREBASE_SERVICE_ACCOUNT (or FIREBASE_DB_SECRET) and restart the app.' }); try { const r = await pushAllVotes(); log(req, 'admin', 'FIREBASE_PUSH_VOTES', null, r); res.json({ ok: true, ...r }); } catch (e) { res.status(502).json({ error: e.message }); } });
app.post('/api/admin/firebase/pull', admin, async (req, res) => { if (!rtdbReady()) return res.status(400).json({ error: 'Firebase is not connected yet. In Hostinger add FIREBASE_SERVICE_ACCOUNT (or FIREBASE_DB_SECRET) and restart the app.' }); try { const r = await pullMembers(); log(req, 'admin', 'FIREBASE_PULL', null, r); res.json({ ok: true, ...r }); } catch (e) { res.status(502).json({ error: e.message }); } });
app.get('/api/admin/participation/:id', admin, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id); if (!e) return res.status(404).json({ error: 'Election not found.' });
  const voted = db.prepare('SELECT m.member_id,m.name,m.mobile,m.category,p.voted_at,p.via FROM voter_participation p JOIN members m ON m.id=p.member_id WHERE p.election_id=? ORDER BY p.voted_at DESC').all(e.id);
  const pending = db.prepare('SELECT member_id,name,mobile,category FROM members WHERE eligible=1 AND id NOT IN (SELECT member_id FROM voter_participation WHERE election_id=?) ORDER BY member_id').all(e.id);
  if (req.query.log) log(req, 'admin', 'VOTER_LIST_VIEWED', e.id, { voted: voted.length, pending: pending.length });
  res.json({ election: view(e), voted, pending });
});
app.get('/api/admin/mis/:id', admin, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id); if (!e) return res.status(404).json({ error: 'Election not found.' });
  const v = view(e), closed = ['CLOSED', 'RESULTS'].includes(v.status) || !!e.live_candidates;
  res.json({
    status: v.status, eligible: v.eligible, polled: v.polled, turnout: v.turnout,
    categories: db.prepare("SELECT COALESCE(NULLIF(m.category,''),'Uncategorised') cat, COUNT(*) eligible, SUM(CASE WHEN p.id IS NOT NULL THEN 1 ELSE 0 END) voted FROM members m LEFT JOIN voter_participation p ON p.member_id=m.id AND p.election_id=? WHERE m.eligible=1 GROUP BY cat ORDER BY cat").all(e.id),
    hourly: db.prepare("SELECT substr(voted_at,1,13)||':00:00Z' h, COUNT(*) n FROM voter_participation WHERE election_id=? GROUP BY 1 ORDER BY 1").all(e.id),
    first_vote: db.prepare('SELECT MIN(voted_at) t FROM voter_participation WHERE election_id=?').get(e.id).t, last_vote: db.prepare('SELECT MAX(voted_at) t FROM voter_participation WHERE election_id=?').get(e.id).t,
    results: closed ? tally(e.id) : null   // candidate-wise counts stay hidden until voting closes (ballot secrecy)
  });
});
// Integrity check: audit chain + ballots-vs-voters reconciliation + fingerprints that can be recorded for later verification
app.get('/api/admin/integrity', admin, (req, res) => {
  let prev = '', n = 0, bad = null;
  for (const r of db.prepare('SELECT * FROM audit_log WHERE hash IS NOT NULL ORDER BY id').all()) { if (chainHash(prev, r) !== r.hash) { bad = r.id; break; } prev = r.hash; n++; }
  const dig = rows => crypto.createHash('sha256').update(rows.join('\n')).digest('hex');
  const elections = db.prepare('SELECT * FROM elections ORDER BY id').all().map(e => {
    const p = db.prepare('SELECT m.member_id FROM voter_participation p JOIN members m ON m.id=p.member_id WHERE p.election_id=? ORDER BY m.member_id').all(e.id).map(x => x.member_id), b = db.prepare('SELECT txn_id,candidate_id FROM ballots WHERE election_id=? ORDER BY txn_id').all(e.id).map(x => x.txn_id + ':' + x.candidate_id);
    return { code: e.code, post: e.post, voters: p.length, ballots: b.length, match: p.length === b.length, voters_fingerprint: dig(p), ballots_fingerprint: dig(b) };
  });
  const out = { checked_at: new Date().toISOString(), audit_entries: n, audit_chain_ok: bad === null, first_bad_entry: bad, all_match: elections.every(e => e.match), elections };
  log(req, 'admin', 'INTEGRITY_CHECK', null, { chain_ok: out.audit_chain_ok, all_match: out.all_match });
  res.json(out);
});
app.post('/api/admin/audit', admin, limit(5, 60000), (req, res) => {
  const { key, reason, election_id } = req.body;
  if (key !== AUDIT_KEY) { log(req, 'admin', 'RESTRICTED_AUDIT_DENIED', election_id, reason); return res.status(403).json({ error: 'Invalid audit key.' }); }
  if (!reason || reason.trim().length < 10) return res.status(400).json({ error: 'Please give a written reason (at least 10 characters).' });
  if (!election_id || !db.prepare('SELECT 1 FROM elections WHERE id=?').get(election_id)) return res.status(400).json({ error: 'Please choose an election.' });
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
const openStatus = m => db.prepare('SELECT * FROM elections').all().filter(e => status(e) === 'OPEN').map(e => ({ id: e.id, code: e.code, post: e.post, voted: !!db.prepare('SELECT 1 FROM voter_participation WHERE election_id=? AND member_id=?').get(e.id, m.id) }));
app.post('/api/member/lookup', limit(10, 600000), async (req, res) => {
  const mobile = norm(req.body.mobile), m = await findMember(mobile);
  if (!m) { log(req, 'member', 'LOOKUP_NOT_FOUND', null, 'XXXXXX' + mobile.slice(-4)); return res.status(404).json({ error: 'This mobile number is not registered for this election.' }); }
  const elections = openStatus(m), all = db.prepare('SELECT * FROM elections').all().map(status);
  const state = !elections.length ? (all.includes('UPCOMING') ? 'not_started' : 'ended') : elections.every(e => e.voted) ? 'all_voted' : 'can_vote';
  res.json({ name: m.name || 'Member', member_id: m.member_id, elections, state, fb: fbConfig() });
});
app.post('/api/otp/request', limit(6, 600000), async (req, res) => {
  const mobile = norm(req.body.mobile), m = await findMember(mobile);
  if (!m) { log(req, 'member', 'OTP_REJECTED_NOT_ELIGIBLE', null, 'XXXXXX' + mobile.slice(-4)); return res.status(403).json({ error: 'Mobile number is not registered for this election.' }); }
  const els = db.prepare('SELECT * FROM elections').all().map(status), ops = openStatus(m);
  if (ops.length && ops.every(e => e.voted)) { log(req, 'member:' + m.member_id, 'OTP_BLOCKED_ALREADY_VOTED'); return res.status(400).json({ error: 'You have already voted. Voting is allowed only once, so no OTP will be sent.' }); }
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
  const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, { member_id: m.id, exp: Date.now() + 15 * 60000, via: 'otp' }); res.json({ session: t, name: m.name });
});
const last10 = n => String(n || '').replace(/\D/g, '').slice(-10);
// ---- Firebase Authentication (Phone / SMS OTP). The browser signs in with Firebase; here we verify Google's signed ID token and match the phone number to the member ----
let fbCerts = { exp: 0, keys: {} }; const fbUsed = new Map();
async function fbKeys() {
  if (Date.now() < fbCerts.exp) return fbCerts.keys;
  const r = await fetch(process.env.FIREBASE_CERTS_URL || 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
  if (!r.ok) throw new Error('Could not fetch Google signing keys');
  const m = /max-age=(\d+)/.exec(r.headers.get('cache-control') || ''); fbCerts = { keys: await r.json(), exp: Date.now() + (m ? +m[1] : 3600) * 1000 };
  return fbCerts.keys;
}
async function verifyFirebaseToken(idToken) {
  const [h, p, sig] = String(idToken || '').split('.'); if (!sig) throw new Error('Malformed token');
  const header = JSON.parse(Buffer.from(h, 'base64url')), pl = JSON.parse(Buffer.from(p, 'base64url')), cert = (await fbKeys())[header.kid], pid = process.env.FIREBASE_PROJECT_ID, now = Date.now() / 1000;
  if (header.alg !== 'RS256' || !cert) throw new Error('Unknown signing key');
  if (!crypto.createVerify('RSA-SHA256').update(h + '.' + p).verify(cert, Buffer.from(sig, 'base64url'))) throw new Error('Bad signature');
  if (pl.aud !== pid || pl.iss !== 'https://securetoken.google.com/' + pid) throw new Error('Token is for a different project');
  if (!(pl.exp > now) || pl.iat > now + 60 || !pl.sub) throw new Error('Token expired');
  if (now - (pl.auth_time || 0) > 300) throw new Error('Sign-in is too old');
  return pl;
}
app.post('/api/firebase/verify', limit(10, 600000), async (req, res) => {
  if (!fbConfig()) return res.status(503).json({ error: 'Firebase sign-in is not set up yet. Please use another option.' });
  try {
    const pl = await verifyFirebaseToken(req.body.idToken), mobile = norm(req.body.mobile), tid = crypto.createHash('sha256').update(String(req.body.idToken)).digest('hex');
    for (const [k, e] of fbUsed) if (e < Date.now()) fbUsed.delete(k);
    if (fbUsed.has(tid)) throw new Error('This sign-in was already used');
    if (pl.firebase?.sign_in_provider !== 'phone' || !pl.phone_number || last10(pl.phone_number) !== mobile) { log(req, 'member', 'FIREBASE_NUMBER_MISMATCH', null, 'XXXXXX' + mobile.slice(-4)); throw new Error('The verified phone number does not match.'); }
    const m = await findMember(mobile);
    if (!m) { log(req, 'member', 'FIREBASE_REJECTED_NOT_ELIGIBLE', null, 'XXXXXX' + mobile.slice(-4)); return res.status(403).json({ error: 'Mobile number is not registered for this election.' }); }
    const ops = openStatus(m);
    if (!ops.length) return res.status(400).json({ error: 'There is no election open for voting right now.' });
    if (ops.every(e => e.voted)) { log(req, 'member:' + m.member_id, 'FIREBASE_BLOCKED_ALREADY_VOTED'); return res.status(400).json({ error: 'You have already voted. Voting is allowed only once.' }); }
    fbUsed.set(tid, Date.now() + 600000);
    const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, { member_id: m.id, exp: Date.now() + 15 * 60000, via: 'firebase-sms' });
    log(req, 'member:' + m.member_id, 'FIREBASE_SESSION_STARTED'); res.json({ session: t, name: m.name });
  } catch (e) { log(req, 'member', 'FIREBASE_VERIFY_FAILED', null, String(e.message).slice(0, 80)); res.status(401).json({ error: 'Could not verify your phone number. Please try again.' }); }
});
app.get('/api/ballot', voter, (req, res) => res.json({ elections: db.prepare('SELECT * FROM elections').all().map(view).filter(e => e.status === 'OPEN').map(e => ({ ...e, voted: !!db.prepare('SELECT 1 FROM voter_participation WHERE election_id=? AND member_id=?').get(e.id, req.member) })) }));
app.post('/api/vote', voter, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.body.election_id);
  if (!e || status(e) !== 'OPEN') return res.status(400).json({ error: status(e || { start_at: 0, end_at: 0 }) === 'UPCOMING' ? 'Voting has not started yet.' : 'Voting has ended.' });
  if (!db.prepare('SELECT 1 FROM candidates WHERE id=? AND election_id=? AND active=1').get(req.body.candidate_id, e.id)) return res.status(400).json({ error: 'Invalid candidate.' });
  const txn = 'TX-' + crypto.randomBytes(8).toString('hex').toUpperCase(), at = new Date().toISOString();
  try {
    db.transaction(() => {   // both rows succeed or neither; UNIQUE(election_id,member_id) blocks races
      db.prepare('INSERT INTO voter_participation(election_id,member_id,voted_at,via) VALUES(?,?,?,?)').run(e.id, req.member, at, req.via);
      db.prepare('INSERT INTO ballots(txn_id,election_id,candidate_id) VALUES(?,?,?)').run(txn, e.id, req.body.candidate_id);
    })();
    log(req, 'member', 'VOTE_RECORDED', e.id, 'ok'); res.json({ ok: true, txn });
    fbRecordVote(e, db.prepare('SELECT * FROM members WHERE id=?').get(req.member), req.body.candidate_id, txn, at, req.via);
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
// Always answer API problems with JSON (never an HTML error page), so the screens can show a clear message
app.use('/api', (req, res) => res.status(404).json({ error: `Server is out of date: ${req.method} ${req.originalUrl.split('?')[0]} does not exist. Upload the latest server.js and redeploy.` }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'The upload is too large. Files up to 20 MB are supported.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'The upload was not valid. Please try again.' });
  console.error('ERROR', err); res.status(500).json({ error: 'Server error. Please try again.' });
});
app.listen(process.env.PORT || 3000, () => console.log('Election portal listening on', process.env.PORT || 3000, 'db:', DB_FILE));
// On start: load members from Firebase (so they survive redeploys); if Firebase has none yet, send the local ones up. Then keep the local copy fresh every minute.
if (rtdbReady()) {
  setTimeout(async () => { try { const w = await memberPath(); if (w.path) console.log('Members loaded from Firebase:', JSON.stringify((({ problems, ...x }) => x)(await pullMembers()))); else if (db.prepare('SELECT COUNT(*) c FROM members').get().c) console.log('Members sent to Firebase:', await pushAllMembers()); } catch (e) { console.error('Firebase start-up sync failed:', e.message); } }, 1500);
  setInterval(() => { pullMembers().catch(e => console.error('Firebase background sync failed:', e.message)); }, 60000).unref?.();
}
