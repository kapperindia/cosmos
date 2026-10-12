// Run: npm install && ADMIN_PASSWORD=xxx AUDIT_KEY=yyy npm start   (use behind HTTPS)
const express = require('express'), { DatabaseSync } = require('node:sqlite'), crypto = require('crypto'), path = require('path'), fs = require('fs');  // node:sqlite is built into Node 22: no native build needed
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
// WhatsApp OTP delivery (WhatsApp Cloud API, approved "authentication" template). Env: WA_ACCESS_TOKEN, WA_PHONE_NUMBER_ID, WA_OTP_TEMPLATE; optional WA_OTP_LANG (default en), WA_COUNTRY_CODE (default 91)
const waOtpReady = () => !!(process.env.WA_ACCESS_TOKEN && process.env.WA_PHONE_NUMBER_ID && process.env.WA_OTP_TEMPLATE);
async function sendWhatsAppOtp(mobile, otp) {
  try {
    const r = await fetch(`${process.env.WA_GRAPH_URL || 'https://graph.facebook.com/v21.0'}/${process.env.WA_PHONE_NUMBER_ID}/messages`, { method: 'POST', headers: { Authorization: 'Bearer ' + process.env.WA_ACCESS_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify({ messaging_product: 'whatsapp', to: (process.env.WA_COUNTRY_CODE || '91') + mobile, type: 'template', template: { name: process.env.WA_OTP_TEMPLATE, language: { code: process.env.WA_OTP_LANG || 'en' }, components: [{ type: 'body', parameters: [{ type: 'text', text: otp }] }, { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: otp }] }] } }) });
    if (!r.ok) { const d = await r.json().catch(() => ({})); console.error('WhatsApp OTP failed', r.status, d.error?.message || ''); return false; }
    return true;
  } catch (e) { console.error('WhatsApp OTP error', e.message); return false; }
}
const sendEmail = async (to, subject, text) => { if (!to) return false; console.log(`[EMAIL ${to}] ${subject}: ${text}`); return true; };

const norm = m => String(m || '').replace(/\D/g, '').slice(-10), hash = s => crypto.createHash('sha256').update(s).digest('hex');
const status = e => { const n = Date.now(); if (e.locked) return 'LOCKED'; if (n < Date.parse(e.start_at)) return 'UPCOMING'; if (n <= Date.parse(e.end_at)) return 'OPEN'; return n >= Date.parse(e.result_at || e.end_at) ? 'RESULTS' : 'CLOSED'; };
const hits = new Map(), limit = (n, ms) => (req, res, next) => { const k = req.ip + req.path, now = Date.now(), a = (hits.get(k) || []).filter(t => now - t < ms); a.push(now); hits.set(k, a); a.length > n ? res.status(429).json({ error: 'Too many attempts. Please try again later.' }) : next(); };
const adminTokens = new Set(), sessions = new Map();
const app = express(); app.set('trust proxy', 1); app.use(express.json({ limit: '80mb', verify: (req, res, buf) => { if (req.originalUrl.startsWith('/api/wa/webhook')) req.rawBody = buf; } }));
// Mark the database "changed" after any successful write so the background job backs it up
let dirty = false; app.use((req, res, next) => { if (req.method !== 'GET' && req.path.startsWith('/api/')) res.on('finish', () => { if (res.statusCode < 400) dirty = true; }); next(); });

app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:" }); next(); });
app.get('/health', (_, res) => res.send('ok'));
// Public privacy policy page (required by WhatsApp/Meta and good practice). Set ORG_NAME and CONTACT_EMAIL in the host's environment variables.
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
<li><b>Verification data:</b> a one-time password (stored only in scrambled form and deleted after use or expiry), or, if you choose WhatsApp verification, the WhatsApp number that sends us the verification code.</li>
<li><b>Security logs:</b> actions taken on the portal (for example OTP requests, votes cast, commissioner actions) with the time and IP address, to detect misuse.</li></ul>
<h2>2. How we use it</h2><ul>
<li>To confirm you are a registered member and are allowed to vote.</li>
<li>To send you a one-time password by SMS, or verify you through WhatsApp, and to send election notices.</li>
<li>To make sure each member votes only once, to count votes, to show turnout and results, and to give the Election Commissioner voter and yet-to-vote lists.</li>
<li>To keep election records that can be checked later if a question is raised.</li></ul>
<p>We do not sell your information, use it for advertising, or share it for marketing.</p>
<h2>3. WhatsApp verification</h2>
<p>If you choose "Verify with WhatsApp", you send a one-time code from your own WhatsApp to the association's WhatsApp number. WhatsApp (Meta) tells us the number the message came from, and we use it only to confirm that it matches your registered mobile number. We do not read your other chats, contacts or profile, and we do not use the number for anything else. WhatsApp's own use of data is governed by Meta's privacy policy.</p>
<h2>4. Secrecy of your vote</h2>
<p>The portal records <i>that</i> you voted separately from <i>what</i> you chose. Ballots carry no member ID or time, so a vote cannot be linked back to a voter, not even by the Election Commissioner. Candidate-wise counts are shown only as the election rules allow.</p>
<h2>5. Who can see your information</h2><ul>
<li>The Election Commissioner and authorised officials can see the member register and the voted / yet-to-vote lists.</li>
<li>Our service providers who run the portal: the web host, the SMS and WhatsApp message providers, and the cloud storage used for backups. They handle data only to provide these services.</li>
<li>Authorities, where the law requires it.</li></ul>
<h2>6. Storage, security and retention</h2>
<p>Data is stored on secured servers and in private cloud storage. Access to commissioner functions needs a password. Backups are kept so records survive system changes. Because the association's elections must be verifiable, voting records, the audit log and uploaded member files are kept permanently and cannot be edited or deleted. Other member details are kept while you remain a member and as long as needed for the association's records.</p>
<h2>7. Cookies and tracking</h2>
<p>The portal does not use advertising cookies or third-party trackers.</p>
<h2>8. Your choices and rights</h2>
<p>You may ask to see the information we hold about you, to correct wrong details (such as your mobile number or email), or to ask questions about how it is used. Election records already created cannot be erased, as explained above. Contact us at the address below.</p>
<h2>9. Children</h2><p>The portal is for adult members of the association and is not intended for children.</p>
<h2>10. Changes to this policy</h2><p>If we change this policy, the new version will be posted on this page with a new date.</p>
<h2>11. Contact</h2><p>For privacy questions or requests, contact: <b>${mail}</b> (${org} Election Commissioner).</p>
</main></body></html>`);
});

// Works whether index.html sits in ./public/ or in the repo root (only index.html is ever served from the root, never server.js or the database)
const PUB = path.join(__dirname, 'public'), HOME = [path.join(PUB, 'index.html'), path.join(__dirname, 'index.html')].find(f => fs.existsSync(f));
if (fs.existsSync(PUB)) app.use(express.static(PUB));
app.get('/', (_, res) => HOME ? res.sendFile(HOME) : res.status(500).send('index.html not found. Place it in the public/ folder.'));
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
setInterval(() => { if (dirty) backupNow(false); }, 20000);
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
  res.json({ valid: good.length, errors, added: preview.filter(x => x.status === 'new').length, updated: preview.filter(x => x.status === 'update').length, preview: req.body.dry ? preview : undefined, imported: !req.body.dry, saved });
});
app.post('/api/admin/members/add', admin, (req, res) => {
  const mid = String(req.body.member_id || '').trim(), mob = norm(req.body.mobile), em = String(req.body.email || '').trim();
  if (!mid) return res.status(400).json({ error: 'Member ID is required.' });
  if (mob.length !== 10 || !/^[6-9]/.test(mob)) return res.status(400).json({ error: 'Enter a valid 10-digit mobile number.' });
  if (em && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.status(400).json({ error: 'Invalid email address.' });
  if (db.prepare('SELECT 1 FROM members WHERE member_id=?').get(mid)) return res.status(400).json({ error: 'This Member ID already exists.' });
  if (db.prepare('SELECT 1 FROM members WHERE mobile=?').get(mob)) return res.status(400).json({ error: 'This mobile number already belongs to another member.' });
  db.prepare('INSERT INTO members(member_id,name,mobile,email,category,eligible) VALUES(?,?,?,?,?,1)').run(mid, String(req.body.name || '').trim(), mob, em, String(req.body.category || '').trim());
  log(req, 'admin', 'MEMBER_ADD', null, { member_id: mid });
  res.json({ ok: true });
});
app.post('/api/admin/members/remove', admin, (req, res) => {
  const mid = String(req.body.member_id || '').trim(), m = db.prepare('SELECT * FROM members WHERE member_id=?').get(mid);
  if (!m) return res.status(404).json({ error: 'Member not found.' });
  if (db.prepare('SELECT 1 FROM voter_participation WHERE member_id=?').get(m.id))
    return res.status(400).json({ error: 'This member has already voted, so the record must be kept for the audit trail. Mark the member as not eligible instead.' });
  db.prepare('DELETE FROM otps WHERE mobile=?').run(m.mobile);
  db.prepare('DELETE FROM members WHERE id=?').run(m.id);
  log(req, 'admin', 'MEMBER_REMOVE', null, { member_id: mid });
  res.json({ ok: true });
});
app.post('/api/admin/members/eligible', admin, (req, res) => {
  const mid = String(req.body.member_id || '').trim(), v = req.body.eligible ? 1 : 0;
  if (!db.prepare('UPDATE members SET eligible=? WHERE member_id=? RETURNING id').get(v, mid)) return res.status(404).json({ error: 'Member not found.' });
  log(req, 'admin', v ? 'MEMBER_ELIGIBLE' : 'MEMBER_INELIGIBLE', null, { member_id: mid });
  res.json({ ok: true });
});
app.get('/api/admin/members', admin, (req, res) => {
  const q = `%${req.query.q || ''}%`, p = Math.max(0, +req.query.page || 0);
  const rows = db.prepare('SELECT member_id,name,mobile,email,eligible FROM members WHERE member_id LIKE ? OR name LIKE ? OR mobile LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT 20000').all(q, q, q, q);
  res.json({ rows, total: db.prepare('SELECT COUNT(*) c FROM members WHERE member_id LIKE ? OR name LIKE ? OR mobile LIKE ? OR email LIKE ?').get(q, q, q, q).c, uploads: db.prepare('SELECT * FROM uploads ORDER BY id DESC LIMIT 5').all() });
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
// Voted / yet-to-vote lists (who participated, never whom they voted for)
app.get('/api/admin/participation/:id', admin, (req, res) => {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id); if (!e) return res.status(404).json({ error: 'Election not found.' });
  const voted = db.prepare('SELECT m.member_id,m.name,m.mobile,m.category,p.voted_at FROM voter_participation p JOIN members m ON m.id=p.member_id WHERE p.election_id=? ORDER BY p.voted_at DESC').all(e.id);
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
app.post('/api/member/lookup', limit(10, 600000), (req, res) => {
  const mobile = norm(req.body.mobile), m = db.prepare('SELECT id,name,member_id FROM members WHERE mobile=? AND eligible=1').get(mobile);
  if (!m) { log(req, 'member', 'LOOKUP_NOT_FOUND', null, 'XXXXXX' + mobile.slice(-4)); return res.status(404).json({ error: 'This mobile number is not registered for this election.' }); }
  const elections = openStatus(m), all = db.prepare('SELECT * FROM elections').all().map(status);
  const state = !elections.length ? (all.includes('UPCOMING') ? 'not_started' : 'ended') : elections.every(e => e.voted) ? 'all_voted' : 'can_vote';
  res.json({ name: m.name || 'Member', member_id: m.member_id, elections, state, wa: !!(process.env.WA_BUSINESS_NUMBER && process.env.WA_APP_SECRET), wa_otp: waOtpReady() });
});
app.post('/api/otp/request', limit(6, 600000), async (req, res) => {
  const ch = req.body.channel === 'whatsapp' ? 'whatsapp' : 'sms';
  if (ch === 'whatsapp' && !waOtpReady()) return res.status(503).json({ error: 'OTP on WhatsApp is not set up yet. Please use the SMS OTP.' });
  const mobile = norm(req.body.mobile), m = db.prepare('SELECT * FROM members WHERE mobile=? AND eligible=1').get(mobile);
  if (!m) { log(req, 'member', 'OTP_REJECTED_NOT_ELIGIBLE', null, 'XXXXXX' + mobile.slice(-4)); return res.status(403).json({ error: 'Mobile number is not registered for this election.' }); }
  const els = db.prepare('SELECT * FROM elections').all().map(status), ops = openStatus(m);
  if (ops.length && ops.every(e => e.voted)) { log(req, 'member:' + m.member_id, 'OTP_BLOCKED_ALREADY_VOTED'); return res.status(400).json({ error: 'You have already voted. Voting is allowed only once, so no OTP will be sent.' }); }
  if (!els.includes('OPEN')) return res.status(400).json({ error: els.includes('UPCOMING') ? 'Voting has not started yet.' : 'Voting has ended.' });
  const o = db.prepare('SELECT * FROM otps WHERE mobile=?').get(mobile);
  if (o && Date.now() - o.sent_at < 30000) return res.status(429).json({ error: 'Please wait 30 seconds before requesting another OTP.' });
  if (o && o.resends >= 5 && Date.now() - o.sent_at < 3600000) return res.status(429).json({ error: 'Too many OTP requests. Please try again later.' });
  const otp = String(crypto.randomInt(100000, 1000000));
  db.prepare('INSERT OR REPLACE INTO otps(mobile,hash,expires,tries,sent_at,resends) VALUES(?,?,?,0,?,?)').run(mobile, hash(otp), Date.now() + cfg().otp_ttl * 1000, Date.now(), (o?.resends || 0) + 1);
  if (ch === 'whatsapp') {
    if (!await sendWhatsAppOtp(mobile, otp)) { db.prepare('DELETE FROM otps WHERE mobile=?').run(mobile); log(req, 'member:' + m.member_id, 'OTP_WHATSAPP_FAILED'); return res.status(502).json({ error: 'Could not send the OTP on WhatsApp right now. Please try the SMS OTP or WhatsApp verification.' }); }
  } else await sendSms(mobile, `Your election OTP is ${otp}. Valid for ${Math.round(cfg().otp_ttl / 60)} minutes. Do not share it.`);
  log(req, 'member:' + m.member_id, 'OTP_GENERATED', null, ch); res.json({ ok: true, channel: ch });
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
// ---- WhatsApp reverse verification: the member SENDS a one-time code to the portal's WhatsApp number; WhatsApp tells us which number it came from ----
// Needs the WhatsApp Business (Meta Cloud API) webhook. Env: WA_BUSINESS_NUMBER (e.g. 919876543210), WA_APP_SECRET, WA_VERIFY_TOKEN
const waPending = new Map(), waByToken = new Map(), last10 = n => String(n || '').replace(/\D/g, '').slice(-10);
setInterval(() => { for (const [c, p] of waPending) if (p.exp < Date.now()) { waPending.delete(c); waByToken.delete(p.token); } }, 60000).unref?.();
const waReady = () => !!(process.env.WA_BUSINESS_NUMBER && process.env.WA_APP_SECRET);
app.post('/api/wa/start', limit(6, 600000), (req, res) => {
  if (!waReady()) return res.status(503).json({ error: 'WhatsApp verification is not set up yet. Please use the OTP option.' });
  const mobile = norm(req.body.mobile), m = db.prepare('SELECT * FROM members WHERE mobile=? AND eligible=1').get(mobile);
  if (!m) { log(req, 'member', 'WA_REJECTED_NOT_ELIGIBLE', null, 'XXXXXX' + mobile.slice(-4)); return res.status(403).json({ error: 'Mobile number is not registered for this election.' }); }
  const ops = openStatus(m);
  if (!ops.length) return res.status(400).json({ error: 'There is no election open for voting right now.' });
  if (ops.every(e => e.voted)) { log(req, 'member:' + m.member_id, 'WA_BLOCKED_ALREADY_VOTED'); return res.status(400).json({ error: 'You have already voted. Voting is allowed only once.' }); }
  for (const [c, p] of waPending) if (p.mobile === mobile) { waPending.delete(c); waByToken.delete(p.token); }
  let code; do code = 'VOTE-' + crypto.randomInt(100000, 1000000); while (waPending.has(code));
  const token = crypto.randomBytes(20).toString('hex'), ttl = 300;
  waPending.set(code, { mobile, member_id: m.id, token, exp: Date.now() + ttl * 1000, verified: false }); waByToken.set(token, code);
  log(req, 'member:' + m.member_id, 'WA_CODE_ISSUED');
  res.json({ code, token, expires_in: ttl, link: `https://wa.me/${String(process.env.WA_BUSINESS_NUMBER).replace(/\D/g, '')}?text=${encodeURIComponent(code)}` });
});
app.get('/api/wa/status', limit(300, 600000), (req, res) => {
  const code = waByToken.get(String(req.query.token || '')), p = code && waPending.get(code);
  if (!p || p.exp < Date.now()) return res.json({ status: 'expired' });
  if (!p.verified) return res.json({ status: 'waiting' });
  const m = db.prepare('SELECT * FROM members WHERE id=? AND eligible=1').get(p.member_id);
  waPending.delete(code); waByToken.delete(p.token);
  if (!m) return res.json({ status: 'expired' });
  const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, { member_id: m.id, exp: Date.now() + 15 * 60000 });
  log(req, 'member:' + m.member_id, 'WA_SESSION_STARTED'); res.json({ status: 'verified', session: t, name: m.name });
});
// Meta calls this once to confirm the webhook URL...
app.get('/api/wa/webhook', (req, res) => {
  if (req.query['hub.mode'] === 'subscribe' && process.env.WA_VERIFY_TOKEN && req.query['hub.verify_token'] === process.env.WA_VERIFY_TOKEN) return res.status(200).send(String(req.query['hub.challenge']));
  res.sendStatus(403);
});
// ...and posts every incoming WhatsApp message here. Requests without a valid Meta signature are ignored.
app.post('/api/wa/webhook', (req, res) => {
  const secret = process.env.WA_APP_SECRET, sig = String(req.get('x-hub-signature-256') || '');
  if (!secret || !req.rawBody) return res.sendStatus(403);
  const want = 'sha256=' + crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return res.sendStatus(403);
  try {
    for (const en of req.body.entry || []) for (const ch of en.changes || []) for (const msg of ch.value?.messages || []) {
      const hit = String(msg.text?.body || '').toUpperCase().match(/VOTE-\d{6}/), p = hit && waPending.get(hit[0]);
      if (!p || p.exp < Date.now() || p.verified) continue;
      if (last10(msg.from) === p.mobile) { p.verified = true; log(req, 'member:' + p.member_id, 'WA_VERIFIED'); }
      else log(req, 'member:' + p.member_id, 'WA_NUMBER_MISMATCH', null, 'sent from XXXXXX' + last10(msg.from).slice(-4));
    }
  } catch (e) { console.error('WA webhook error', e.message); }
  res.sendStatus(200);
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
// Always answer API problems with JSON (never an HTML error page), so the screens can show a clear message
app.use('/api', (req, res) => res.status(404).json({ error: `Server is out of date: ${req.method} ${req.originalUrl.split('?')[0]} does not exist. Upload the latest server.js and redeploy.` }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'The upload is too large. Files up to 20 MB are supported.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'The upload was not valid. Please try again.' });
  console.error('ERROR', err); res.status(500).json({ error: 'Server error. Please try again.' });
});
app.listen(process.env.PORT || 3000, () => console.log('Election portal listening on', process.env.PORT || 3000, 'db:', DB_FILE));
