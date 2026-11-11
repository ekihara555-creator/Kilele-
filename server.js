'use strict';
/* Kilele Exchange backend. Zero npm dependencies; needs Node 22.5+ (node:sqlite).
   Serves public/index.html and the /api/* endpoints the page expects.
   Integrations: CoinGecko (prices), Safaricom Daraja (M-Pesa STK push + B2C), Kraken (hedging). */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const scrypt = promisify(crypto.scrypt);

/* ---------- config ---------- */
const E = process.env;
const CFG = {
  port: Number(E.PORT || 3000),
  dbPath: E.DB_PATH || path.join(__dirname, 'kilele.db'),
  publicUrl: (E.PUBLIC_URL || E.RENDER_EXTERNAL_URL || '').replace(/\/$/, ''),
  trustProxy: E.TRUST_PROXY === '1',
  cgBase: E.COINGECKO_BASE || 'https://api.coingecko.com/api/v3',
  cgKey: E.COINGECKO_KEY || '',
  staleMs: Number(E.PRICE_STALE_MS || 120000),
  krBase: E.KRAKEN_BASE || 'https://api.kraken.com',
  krKey: E.KRAKEN_KEY || '', krSecret: E.KRAKEN_SECRET || '',
  hedgeMode: E.HEDGE_MODE || 'off', // off | validate | live
  hedgeEveryMs: Number(E.HEDGE_EVERY_MS || 60000),
  mpBase: E.MPESA_BASE || 'https://sandbox.safaricom.co.ke',
  mpKey: E.MPESA_KEY || '', mpSecret: E.MPESA_SECRET || '',
  mpShort: E.MPESA_SHORTCODE || '', mpPasskey: E.MPESA_PASSKEY || '',
  mpTxnType: E.MPESA_TXN_TYPE || 'CustomerPayBillOnline', mpPartyB: E.MPESA_PARTYB || E.MPESA_SHORTCODE || '',
  mpCbSecret: E.MPESA_CALLBACK_SECRET || '', mpCbIps: (E.MPESA_CALLBACK_IPS || '').split(',').map(s => s.trim()).filter(Boolean),
  b2cInitiator: E.MPESA_B2C_INITIATOR || '', b2cPassword: E.MPESA_B2C_PASSWORD || '', b2cCert: E.MPESA_B2C_CERT_PATH || '',
  b2cShort: E.MPESA_B2C_SHORTCODE || '', b2cPath: E.MPESA_B2C_PATH || '/mpesa/b2c/v3/paymentrequest',
  adminToken: E.ADMIN_TOKEN || '',
  autoWithdrawMax: Number(E.AUTO_WITHDRAW_MAX_KES || 0), // 0 = every withdrawal waits for admin approval
  dailyWithdrawKes: Number(E.DAILY_WITHDRAW_LIMIT_KES || 300000),
};
const MPESA_ON = !!(CFG.mpKey && CFG.mpSecret && CFG.mpShort && CFG.mpPasskey && CFG.mpCbSecret && CFG.publicUrl);
const B2C_ON = !!(MPESA_ON && CFG.b2cInitiator && CFG.b2cPassword && CFG.b2cCert && fs.existsSync(CFG.b2cCert || '/nonexistent'));
const SECURE = CFG.publicUrl.startsWith('https://');

const SY = ['BTC', 'ETH', 'SOL', 'XRP', 'USDT'];
const NAMES = { BTC: 'Bitcoin', ETH: 'Ethereum', SOL: 'Solana', XRP: 'XRP', USDT: 'Tether' };
const CG_ID = { BTC: 'bitcoin', ETH: 'ethereum', SOL: 'solana', XRP: 'ripple', USDT: 'tether' };
const KR_PAIR = { BTC: 'XBTUSD', ETH: 'ETHUSD', SOL: 'SOLUSD', XRP: 'XRPUSD', USDT: 'USDTUSD' };
const SCALE = { KES: 100, BTC: 1e8, ETH: 1e8, SOL: 1e8, XRP: 1e8, USDT: 1e8 };
const ASSETS = ['KES', ...SY];
const TIERS = [{ n: 'Starter', m: 0, r: .005 }, { n: 'Regular', m: 5e5, r: .0035 }, { n: 'Pro', m: 5e6, r: .002 }, { n: 'Elite', m: 25e6, r: .001 }];

const log = (ev, o) => console.log(JSON.stringify({ t: new Date().toISOString(), ev, ...o }));
class HttpError extends Error { constructor(s, m) { super(m); this.status = s; } }
const sha = s => crypto.createHash('sha256').update(s).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(String(a)), sha(String(b)));
const fmtQty = u => (u / 1e8).toFixed(8).replace(/\.?0+$/, '') || '0';
const fmtKes = c => 'KES ' + (c / 100).toLocaleString('en-KE', { maximumFractionDigits: 2 });

/* ---------- database ---------- */
const db = new DatabaseSync(CFG.dbPath);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, totp_secret TEXT, totp_pending TEXT, totp_step INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS balances(user_id INTEGER NOT NULL REFERENCES users(id), asset TEXT NOT NULL, units INTEGER NOT NULL CHECK(units>=0), PRIMARY KEY(user_id,asset));
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, asset TEXT NOT NULL, delta INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, note TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS trades(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, side TEXT NOT NULL, asset TEXT NOT NULL, kes_cents INTEGER NOT NULL, qty_units INTEGER NOT NULL, fee_cents INTEGER NOT NULL, price REAL NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS trades_user_ts ON trades(user_id,ts);
CREATE TABLE IF NOT EXISTS hedge_batches(id INTEGER PRIMARY KEY, asset TEXT NOT NULL, side TEXT NOT NULL, volume TEXT NOT NULL, status TEXT NOT NULL, txid TEXT, error TEXT, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS hedges(id INTEGER PRIMARY KEY, trade_id INTEGER NOT NULL, asset TEXT NOT NULL, side TEXT NOT NULL, qty_units INTEGER NOT NULL, status TEXT NOT NULL, batch_id INTEGER, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS deposits(id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, phone TEXT NOT NULL, amount_cents INTEGER NOT NULL, checkout_id TEXT UNIQUE, merchant_id TEXT, status TEXT NOT NULL, receipt TEXT UNIQUE, note TEXT, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, method TEXT NOT NULL, dest TEXT NOT NULL, amount_cents INTEGER NOT NULL, fee_cents INTEGER NOT NULL, status TEXT NOT NULL, orig_id TEXT UNIQUE, receipt TEXT, note TEXT, ts INTEGER NOT NULL);
`);
const q = sql => db.prepare(sql);
function tx(fn) { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch (_) { } throw e; } }

/* ledger: user 0 is the house. Customer balances live in `balances` (never negative by CHECK). */
function move(uid, asset, delta, kind, ref) {
  if (uid !== 0) {
    q('INSERT INTO balances(user_id,asset,units) VALUES(?,?,0) ON CONFLICT DO NOTHING').run(uid, asset);
    try { q('UPDATE balances SET units=units+? WHERE user_id=? AND asset=?').run(delta, uid, asset); }
    catch (e) { throw new HttpError(400, 'Not enough ' + asset + '.'); }
  }
  q('INSERT INTO ledger(user_id,asset,delta,kind,ref,ts) VALUES(?,?,?,?,?,?)').run(uid, asset, delta, kind, ref == null ? null : String(ref), Date.now());
}
const note = (uid, t) => q('INSERT INTO activity(user_id,note,ts) VALUES(?,?,?)').run(uid, t, Date.now());
function balances(uid) {
  const o = {}; ASSETS.forEach(a => o[a] = 0);
  q('SELECT asset,units FROM balances WHERE user_id=?').all(uid).forEach(r => { o[r.asset] = r.units / SCALE[r.asset]; });
  return o;
}
const units = (uid, asset) => (q('SELECT units FROM balances WHERE user_id=? AND asset=?').get(uid, asset) || { units: 0 }).units;
const vol30 = uid => q('SELECT COALESCE(SUM(kes_cents),0) v FROM trades WHERE user_id=? AND ts>?').get(uid, Date.now() - 30 * 864e5).v;
function tierOf(volCents) { let i = 0; TIERS.forEach((t, j) => { if (volCents >= t.m * 100) i = j; }); return { ...TIERS[i], next: TIERS[i + 1] || null }; }

/* ---------- http helpers ---------- */
async function httpJson(url, opt = {}) {
  const r = await fetch(url, { ...opt, signal: AbortSignal.timeout(opt.timeout || 15000) });
  const txt = await r.text(); let body = {}; try { body = JSON.parse(txt); } catch (_) { }
  return { status: r.status, body };
}
const limiter = new Map();
function hit(key, max, win) { const n = Date.now(); let e = limiter.get(key); if (!e || e.reset < n) e = { c: 0, reset: n + win }; e.c++; limiter.set(key, e); return e.c <= max; }
setInterval(() => { const n = Date.now(); for (const [k, v] of limiter) if (v.reset < n) limiter.delete(k); q('DELETE FROM sessions WHERE expires_at<?').run(n); }, 60000).unref();
function guard(key, max, win, msg) { if (!hit(key, max, win)) throw new HttpError(429, msg || 'Too many attempts. Try again later.'); }

/* ---------- prices (CoinGecko) ---------- */
let P = { assets: {}, ts: 0 }, held = null;
const clients = new Set();
const pricesPublic = () => ({ assets: P.assets, fresh: SY.every(s => P.assets[s]) && Date.now() - P.ts < CFG.staleMs });
function freshPrice(s) {
  const pub = pricesPublic(), a = P.assets[s];
  if (!pub.fresh || !a || !(a.price > 0)) throw new HttpError(503, 'Prices are unavailable right now. Trading is paused.');
  return a.price;
}
async function pollPrices() {
  try {
    const url = `${CFG.cgBase}/coins/markets?vs_currency=kes&ids=${SY.map(s => CG_ID[s]).join(',')}&sparkline=true&price_change_percentage=24h`;
    const r = await httpJson(url, { headers: CFG.cgKey ? { 'x-cg-demo-api-key': CFG.cgKey } : {} });
    if (r.status !== 200 || !Array.isArray(r.body)) throw new Error('CoinGecko HTTP ' + r.status);
    const next = {};
    for (const s of SY) {
      const x = r.body.find(c => c.id === CG_ID[s]);
      if (!x || !(x.current_price > 0)) throw new Error('missing ' + s);
      const sp = (x.sparkline_in_7d && x.sparkline_in_7d.price) || [x.current_price, x.current_price], t = [];
      for (let i = 0; i < 42; i++) t.push(sp[Math.round(i * (sp.length - 1) / 41)]);
      next[s] = { name: NAMES[s], price: x.current_price, change: x.price_change_percentage_24h || 0, spark: t };
    }
    /* circuit breaker: a >15% jump in one poll is held back until a second poll agrees */
    const old = P.assets;
    const jumped = SY.some(s => old[s] && Math.abs(next[s].price / old[s].price - 1) > .15);
    if (jumped) {
      const agrees = held && SY.every(s => Math.abs(next[s].price / held[s].price - 1) < .05);
      if (!agrees) { held = next; log('price_jump_held', {}); return; }
    }
    held = null; P = { assets: next, ts: Date.now() };
    const msg = `data: ${JSON.stringify(pricesPublic())}\n\n`;
    for (const c of clients) c.write(msg);
  } catch (e) { log('price_poll_failed', { err: e.message }); }
}

/* ---------- auth ---------- */
async function hashPw(pw) { const salt = crypto.randomBytes(16); const h = await scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }); return `s1$${salt.toString('base64')}$${h.toString('base64')}`; }
let DUMMY = null;
async function verifyPw(pw, stored) {
  const [v, s, h] = stored.split('$'); if (v !== 's1') return false;
  const got = await scrypt(pw, Buffer.from(s, 'base64'), 64, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(got, Buffer.from(h, 'base64'));
}
function newSession(res, uid) {
  const tok = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO sessions(id,user_id,expires_at) VALUES(?,?,?)').run(sha(tok).toString('hex'), uid, Date.now() + 7 * 864e5);
  res.setHeader('Set-Cookie', `kl_sid=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${7 * 86400}${SECURE ? '; Secure' : ''}`);
}
function sessionUser(req) {
  const m = /(?:^|;\s*)kl_sid=([\w-]+)/.exec(req.headers.cookie || ''); if (!m) return null;
  return q('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?').get(sha(m[1]).toString('hex'), Date.now()) || null;
}
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; }
function b32dec(s) { let bits = ''; for (const c of s.replace(/=+$/, '')) bits += B32.indexOf(c).toString(2).padStart(5, '0'); const o = []; for (let i = 0; i + 8 <= bits.length; i += 8) o.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(o); }
function totp(secret, step) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', b32dec(secret)).update(c).digest(), o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0');
}
/* returns the matched time-step (must be newer than the last used one, so a code works once) or null */
function checkTotp(secret, code, lastStep, now = Date.now()) {
  code = String(code || '').replace(/\D/g, ''); if (code.length !== 6) return null;
  const cur = Math.floor(now / 30000);
  for (const d of [0, -1, 1]) { const st = cur + d; if (st > lastStep && safeEq(totp(secret, st), code)) return st; }
  return null;
}
function require2fa(u, code) {
  if (!u.totp_secret) return;
  const st = checkTotp(u.totp_secret, code, u.totp_step);
  if (st === null) throw new HttpError(401, 'That code isn’t right.');
  q('UPDATE users SET totp_step=? WHERE id=?').run(st, u.id);
}
const normEmail = e => String(e || '').trim().toLowerCase();
const EMAIL_RE = /^\S+@\S+\.\S+$/;

/* ---------- Daraja (M-Pesa) ---------- */
let mpTok = { t: '', exp: 0 };
async function mpToken() {
  if (mpTok.t && Date.now() < mpTok.exp) return mpTok.t;
  const r = await httpJson(CFG.mpBase + '/oauth/v1/generate?grant_type=client_credentials', { headers: { Authorization: 'Basic ' + Buffer.from(CFG.mpKey + ':' + CFG.mpSecret).toString('base64') } });
  if (r.status !== 200 || !r.body.access_token) throw new Error('Daraja auth failed (' + r.status + ')');
  mpTok = { t: r.body.access_token, exp: Date.now() + ((Number(r.body.expires_in) || 3599) - 60) * 1000 };
  return mpTok.t;
}
async function mpPost(p, body) {
  const r = await httpJson(CFG.mpBase + p, { method: 'POST', headers: { Authorization: 'Bearer ' + await mpToken(), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r;
}
const eatStamp = () => new Date(Date.now() + 3 * 3600e3).toISOString().replace(/\D/g, '').slice(0, 14);
const stkPassword = ts => Buffer.from(CFG.mpShort + CFG.mpPasskey + ts).toString('base64');
const normPhone = p => { p = String(p || '').replace(/[\s+]/g, ''); if (!/^(254|0)[17]\d{8}$/.test(p)) return null; return p.startsWith('0') ? '254' + p.slice(1) : p; };
function stkPush(phone, amount, ref) {
  const ts = eatStamp();
  return mpPost('/mpesa/stkpush/v1/processrequest', {
    BusinessShortCode: CFG.mpShort, Password: stkPassword(ts), Timestamp: ts, TransactionType: CFG.mpTxnType,
    Amount: amount, PartyA: phone, PartyB: CFG.mpPartyB, PhoneNumber: phone,
    CallBackURL: `${CFG.publicUrl}/api/mpesa/callback/${CFG.mpCbSecret}/stk`, AccountReference: 'Kilele', TransactionDesc: 'Kilele deposit ' + ref.slice(0, 8),
  });
}
function stkQuery(checkoutId) { const ts = eatStamp(); return mpPost('/mpesa/stkpushquery/v1/query', { BusinessShortCode: CFG.mpShort, Password: stkPassword(ts), Timestamp: ts, CheckoutRequestID: checkoutId }); }
function b2cCredential() {
  const key = crypto.createPublicKey(fs.readFileSync(CFG.b2cCert));
  return crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(CFG.b2cPassword)).toString('base64');
}
function b2cSend(origId, phone, amount) {
  return mpPost(CFG.b2cPath, {
    OriginatorConversationID: origId, InitiatorName: CFG.b2cInitiator, SecurityCredential: b2cCredential(), CommandID: 'BusinessPayment',
    Amount: amount, PartyA: CFG.b2cShort || CFG.mpShort, PartyB: phone, Remarks: 'Kilele withdrawal', Occasion: 'Withdrawal',
    QueueTimeOutURL: `${CFG.publicUrl}/api/mpesa/b2c/${CFG.mpCbSecret}/timeout`, ResultURL: `${CFG.publicUrl}/api/mpesa/b2c/${CFG.mpCbSecret}/result`,
  });
}

/* deposits: credit exactly once, only for the amount we asked for */
function settleDeposit(dep, ok, receipt, paidCents) {
  return tx(() => {
    if (!ok) { return q("UPDATE deposits SET status='failed' WHERE id=? AND status='pending'").run(dep.id).changes === 1; }
    if (paidCents != null && paidCents !== dep.amount_cents) {
      q("UPDATE deposits SET status='mismatch',note=? WHERE id=? AND status='pending'").run('paid ' + paidCents + ' expected ' + dep.amount_cents, dep.id);
      log('deposit_amount_mismatch', { id: dep.id }); return false;
    }
    const ch = q("UPDATE deposits SET status='done',receipt=? WHERE id=? AND status='pending'").run(receipt, dep.id).changes;
    if (ch !== 1) return false;
    move(dep.user_id, 'KES', dep.amount_cents, 'deposit', dep.id);
    note(dep.user_id, `Deposit of ${fmtKes(dep.amount_cents)} received via M-Pesa`);
    return true;
  });
}
async function reconcileDeposit(dep) {
  if (!dep.checkout_id) return;
  try {
    const r = await stkQuery(dep.checkout_id);
    const rc = r.body && r.body.ResultCode;
    if (rc === undefined || rc === null || r.status >= 400) return; // still processing / not yet known
    if (String(rc) === '0') settleDeposit(dep, true, 'query:' + dep.checkout_id, null);
    else settleDeposit(dep, false);
  } catch (e) { log('stk_query_failed', { id: dep.id, err: e.message }); }
}
async function sweepDeposits() {
  if (!MPESA_ON) return;
  const rows = q("SELECT * FROM deposits WHERE status='pending' AND checkout_id IS NOT NULL AND ts<? AND ts>?").all(Date.now() - 60000, Date.now() - 2 * 3600e3);
  for (const d of rows) await reconcileDeposit(d);
}

/* withdrawals */
function refundWithdrawal(w, status, why) {
  return tx(() => {
    const ch = q('UPDATE withdrawals SET status=?,note=? WHERE id=? AND status IN (\'pending\',\'processing\')').run(status, why || null, w.id).changes;
    if (ch !== 1) return false;
    move(w.user_id, 'KES', w.amount_cents + w.fee_cents, 'withdraw_refund', w.id);
    note(w.user_id, `Withdrawal of ${fmtKes(w.amount_cents)} was not completed and has been returned to your balance`);
    return true;
  });
}
async function sendPayout(w) {
  /* definite API errors refund the customer; network ambiguity leaves it for the result callback / admin */
  if (!B2C_ON) throw new HttpError(503, 'Automatic M-Pesa payouts are not configured.');
  q("UPDATE withdrawals SET status='processing' WHERE id=? AND status IN ('pending','processing')").run(w.id);
  try {
    const r = await b2cSend(w.orig_id, w.dest, w.amount_cents / 100);
    if (r.status === 200 && String(r.body.ResponseCode) === '0') return;
    log('b2c_rejected', { id: w.id, status: r.status });
    refundWithdrawal(w, 'failed', 'B2C rejected: ' + (r.body.errorMessage || r.body.ResponseDescription || r.status));
  } catch (e) { log('b2c_unknown', { id: w.id, err: e.message }); q('UPDATE withdrawals SET note=? WHERE id=?').run('request outcome unknown: needs review', w.id); }
}

/* ---------- Kraken hedging ---------- */
const krakenSign = (urlPath, postData, nonce, secret) =>
  crypto.createHmac('sha512', Buffer.from(secret, 'base64')).update(Buffer.concat([Buffer.from(urlPath), sha(nonce + postData)])).digest('base64');
let nonceSeq = 0;
async function krakenPrivate(method, params = {}) {
  const p = '/0/private/' + method, nonce = String(Date.now() * 1000 + (nonceSeq++ % 1000));
  const body = new URLSearchParams({ nonce, ...params }).toString();
  const r = await httpJson(CFG.krBase + p, { method: 'POST', headers: { 'API-Key': CFG.krKey, 'API-Sign': krakenSign(p, body, nonce, CFG.krSecret), 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  if (r.body && Array.isArray(r.body.error) && r.body.error.length) { const e = new Error('Kraken: ' + r.body.error.join(',')); e.definite = true; throw e; }
  if (r.status !== 200) throw new Error('Kraken HTTP ' + r.status);
  return r.body.result || {};
}
let pairMeta = { at: 0, v: {} };
async function getPairMeta() {
  if (Date.now() - pairMeta.at < 6 * 3600e3) return pairMeta.v;
  const r = await httpJson(`${CFG.krBase}/0/public/AssetPairs?pair=${Object.values(KR_PAIR).join(',')}`);
  const v = {};
  Object.values(r.body.result || {}).forEach(x => { const s = SY.find(k => KR_PAIR[k] === x.altname); if (s) v[s] = { ordermin: parseFloat(x.ordermin), dec: x.lot_decimals }; });
  if (!SY.every(s => v[s])) throw new Error('could not load Kraken pair rules');
  pairMeta = { at: Date.now(), v }; return v;
}
async function resolveUnknownBatches() {
  const rows = q("SELECT * FROM hedge_batches WHERE status='unknown' AND ts<?").all(Date.now() - 120000);
  for (const b of rows) {
    const open = await krakenPrivate('OpenOrders', { userref: String(b.id) }), closed = await krakenPrivate('ClosedOrders', { userref: String(b.id) });
    const ids = [...Object.keys(open.open || {}), ...Object.keys(closed.closed || {})];
    tx(() => {
      if (ids.length) { q("UPDATE hedge_batches SET status='sent',txid=? WHERE id=?").run(ids[0], b.id); q("UPDATE hedges SET status='sent' WHERE batch_id=?").run(b.id); }
      else { q("UPDATE hedge_batches SET status='failed',error='not found at venue; released' WHERE id=?").run(b.id); q("UPDATE hedges SET status='pending',batch_id=NULL WHERE batch_id=?").run(b.id); }
    });
  }
}
let hedgeBusy = false;
async function hedgeRun() {
  if (CFG.hedgeMode === 'off' || hedgeBusy) return; hedgeBusy = true;
  try {
    if (CFG.hedgeMode === 'live') await resolveUnknownBatches();
    const meta = await getPairMeta();
    for (const a of SY) {
      const rows = q("SELECT id,side,qty_units FROM hedges WHERE asset=? AND status='pending'").all(a); if (!rows.length) continue;
      const ids = rows.map(r => r.id), ph = ids.map(() => '?').join(',');
      const net = rows.reduce((t, r) => t + (r.side === 'buy' ? r.qty_units : -r.qty_units), 0);
      if (net === 0) { q(`UPDATE hedges SET status='netted' WHERE id IN (${ph})`).run(...ids); continue; }
      const side = net > 0 ? 'buy' : 'sell', m = meta[a], vol = Math.floor(Math.abs(net) / 1e8 * 10 ** m.dec + 1e-9) / 10 ** m.dec;
      if (vol < m.ordermin) continue; // too small for the venue; wait for more flow
      const validate = CFG.hedgeMode === 'validate';
      const bid = tx(() => { const id = Number(q('INSERT INTO hedge_batches(asset,side,volume,status,ts) VALUES(?,?,?,?,?)').run(a, side, vol.toFixed(m.dec), 'sending', Date.now()).lastInsertRowid); q(`UPDATE hedges SET status='batched',batch_id=? WHERE id IN (${ph})`).run(id, ...ids); return id; });
      try {
        const r = await krakenPrivate('AddOrder', { ordertype: 'market', type: side, pair: KR_PAIR[a], volume: vol.toFixed(m.dec), userref: String(bid), ...(validate ? { validate: 'true' } : {}) });
        const st = validate ? 'validated' : 'sent', txid = (r.txid && r.txid[0]) || null;
        tx(() => { q('UPDATE hedge_batches SET status=?,txid=? WHERE id=?').run(st, txid, bid); q('UPDATE hedges SET status=? WHERE batch_id=?').run(st, bid); });
        log('hedge_' + st, { asset: a, side, volume: vol, txid });
      } catch (e) {
        if (e.definite) tx(() => { q("UPDATE hedge_batches SET status='failed',error=? WHERE id=?").run(e.message, bid); q("UPDATE hedges SET status='pending',batch_id=NULL WHERE batch_id=?").run(bid); });
        else q("UPDATE hedge_batches SET status='unknown',error=? WHERE id=?").run(e.message, bid);
        log('hedge_error', { asset: a, err: e.message });
      }
    }
  } catch (e) { log('hedge_run_failed', { err: e.message }); } finally { hedgeBusy = false; }
}

/* ---------- API handlers ---------- */
const needUser = u => { if (!u) throw new HttpError(401, 'Please sign in.'); return u; };
const meOf = u => {
  const v = vol30(u.id), t = tierOf(v), n = t.next;
  return {
    email: u.email, bal: balances(u.id), vol: v / 100, twofa: !!u.totp_secret,
    tier: { n: t.n, m: t.m, r: t.r, next: n ? { n: n.n, m: n.m, r: n.r } : null },
    activity: q('SELECT note,ts FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 8').all(u.id),
  };
};
const H = {};
H.register = async ({ b, res, ip }) => {
  guard('reg:' + ip, 10, 3600e3);
  const email = normEmail(b.email), pw = String(b.password || '');
  if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address.');
  if (pw.length < 10) throw new HttpError(400, 'Password must be at least 10 characters.');
  if (pw.length > 200) throw new HttpError(400, 'Password is too long.');
  const hash = await hashPw(pw);
  let id;
  try { id = Number(q('INSERT INTO users(email,pw_hash,created_at) VALUES(?,?,?)').run(email, hash, Date.now()).lastInsertRowid); }
  catch (e) { throw new HttpError(409, 'An account with that email already exists. Try signing in.'); }
  newSession(res, id); return { ok: true };
};
H.login = async ({ b, res, ip }) => {
  const email = normEmail(b.email), key = 'login:' + ip + '|' + email;
  guard(key, 8, 15 * 60e3, 'Too many sign-in attempts. Wait a few minutes.');
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  if (!DUMMY) DUMMY = await hashPw('dummy-password-for-timing');
  const ok = await verifyPw(String(b.password || ''), u ? u.pw_hash : DUMMY);
  if (!u || !ok) throw new HttpError(401, 'Wrong email or password.');
  if (u.totp_secret) { if (!b.code) return { need2fa: true }; require2fa(u, b.code); }
  limiter.delete(key); newSession(res, u.id); return { ok: true };
};
H.logout = ({ req, res }) => {
  const m = /(?:^|;\s*)kl_sid=([\w-]+)/.exec(req.headers.cookie || '');
  if (m) q('DELETE FROM sessions WHERE id=?').run(sha(m[1]).toString('hex'));
  res.setHeader('Set-Cookie', 'kl_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return { ok: true };
};
H.me = ({ u }) => meOf(needUser(u));
H['2fa/setup'] = ({ u }) => {
  needUser(u); if (u.totp_secret) throw new HttpError(400, 'Two-step sign-in is already on.');
  const s = b32enc(crypto.randomBytes(20)); q('UPDATE users SET totp_pending=? WHERE id=?').run(s, u.id); return { secret: s };
};
H['2fa/enable'] = ({ u, b }) => {
  needUser(u); guard('2fa:' + u.id, 10, 15 * 60e3);
  if (!u.totp_pending) throw new HttpError(400, 'Start setup first.');
  const st = checkTotp(u.totp_pending, b.code, 0); if (st === null) throw new HttpError(400, 'That code isn’t right.');
  q('UPDATE users SET totp_secret=totp_pending,totp_pending=NULL,totp_step=? WHERE id=?').run(st, u.id);
  note(u.id, 'Two-step sign-in turned on'); return { ok: true };
};
H['2fa/disable'] = ({ u, b }) => {
  needUser(u); guard('2fa:' + u.id, 10, 15 * 60e3); require2fa(u, b.code);
  q('UPDATE users SET totp_secret=NULL,totp_pending=NULL,totp_step=0 WHERE id=?').run(u.id); note(u.id, 'Two-step sign-in turned off'); return { ok: true };
};
H.trade = ({ u, b }) => {
  needUser(u); guard('trade:' + u.id, 30, 60e3);
  const side = b.side, asset = b.asset, amount = Number(b.amount);
  if (side !== 'buy' && side !== 'sell') throw new HttpError(400, 'Choose buy or sell.');
  if (!SY.includes(asset) || !Number.isFinite(amount) || !(amount > 0)) throw new HttpError(400, 'Enter an amount to continue.');
  const price = freshPrice(asset);
  const out = tx(() => {
    const rate = tierOf(vol30(u.id)).r; let kes, qty, fee, msg;
    if (side === 'buy') {
      kes = Math.round(amount * 100); if (kes < 10000) throw new HttpError(400, 'Minimum trade is KES 100.');
      if (units(u.id, 'KES') < kes) throw new HttpError(400, 'Not enough KES.');
      fee = Math.round(kes * rate); qty = Math.floor((kes - fee) / 100 / price * 1e8);
      if (qty <= 0) throw new HttpError(400, 'Amount is too small.');
      move(u.id, 'KES', -kes, 'trade', null); move(u.id, asset, qty, 'trade', null);
      move(0, 'KES', kes, 'trade', null); move(0, asset, -qty, 'trade', null);
      msg = `Bought ${fmtQty(qty)} ${asset}.`;
    } else {
      qty = Math.round(amount * 1e8); if (qty <= 0) throw new HttpError(400, 'Amount is too small.');
      if (units(u.id, asset) < qty) throw new HttpError(400, 'Not enough ' + asset + '.');
      const gross = Math.floor(qty / 1e8 * price * 100); if (gross < 10000) throw new HttpError(400, 'Minimum trade is KES 100.');
      fee = Math.round(gross * rate); kes = gross;
      move(u.id, asset, -qty, 'trade', null); move(u.id, 'KES', gross - fee, 'trade', null);
      move(0, asset, qty, 'trade', null); move(0, 'KES', -(gross - fee), 'trade', null);
      msg = `Sold ${fmtQty(qty)} ${asset}.`;
    }
    const tid = Number(q('INSERT INTO trades(user_id,side,asset,kes_cents,qty_units,fee_cents,price,ts) VALUES(?,?,?,?,?,?,?,?)').run(u.id, side, asset, kes, qty, fee, price, Date.now()).lastInsertRowid);
    q('INSERT INTO hedges(trade_id,asset,side,qty_units,status,ts) VALUES(?,?,?,?,?,?)').run(tid, asset, side, qty, CFG.hedgeMode === 'off' ? 'skipped' : 'pending', Date.now());
    note(u.id, msg.replace('.', '') + ' for ' + fmtKes(side === 'buy' ? kes : kes - fee));
    return { summary: msg };
  });
  return out; // hedged by the timer (HEDGE_EVERY_MS) so opposite flow nets out
};
H['deposit/mpesa'] = async ({ u, b }) => {
  needUser(u); if (!MPESA_ON) throw new HttpError(503, 'Deposits are not available right now.');
  guard('dep:' + u.id, 6, 600e3);
  const phone = normPhone(b.phone), amt = Number(b.amount);
  if (!phone) throw new HttpError(400, 'Enter a valid Safaricom number.');
  if (!Number.isInteger(amt) || amt < 10 || amt > 250000) throw new HttpError(400, 'Deposit a whole amount between KES 10 and KES 250,000.');
  const id = crypto.randomUUID();
  q("INSERT INTO deposits(id,user_id,phone,amount_cents,status,ts) VALUES(?,?,?,?,'pending',?)").run(id, u.id, phone, amt * 100, Date.now());
  try {
    const r = await stkPush(phone, amt, id);
    if (r.status !== 200 || String(r.body.ResponseCode) !== '0' || !r.body.CheckoutRequestID) throw new Error('STK rejected ' + r.status + ' ' + (r.body.errorMessage || r.body.ResponseDescription || ''));
    q('UPDATE deposits SET checkout_id=?,merchant_id=? WHERE id=?').run(r.body.CheckoutRequestID, r.body.MerchantRequestID || null, id);
  } catch (e) {
    q("UPDATE deposits SET status='failed',note=? WHERE id=?").run(e.message, id); log('stk_failed', { id, err: e.message });
    throw new HttpError(502, 'We couldn’t send the M-Pesa prompt. Try again.');
  }
  return { id };
};
H['deposit/status'] = async ({ u, params }) => {
  needUser(u); let d = q('SELECT * FROM deposits WHERE id=? AND user_id=?').get(params[0], u.id);
  if (!d) return { status: 'unknown' };
  if (d.status === 'pending' && Date.now() - d.ts > 30000 && MPESA_ON) { await reconcileDeposit(d); d = q('SELECT * FROM deposits WHERE id=?').get(d.id); }
  return { status: d.status === 'done' ? 'done' : (d.status === 'pending' ? 'pending' : 'failed') };
};
H.withdraw = async ({ u, b }) => {
  needUser(u); guard('wd:' + u.id, 5, 3600e3);
  const method = b.method, amt = Number(b.amount), dest0 = String(b.dest || '').trim();
  if (!Number.isInteger(amt) || amt < 500) throw new HttpError(400, 'Minimum withdrawal is KES 500, in whole shillings.');
  let dest;
  if (method === 'mpesa') { dest = normPhone(dest0); if (!dest) throw new HttpError(400, 'Enter a valid Safaricom number.'); if (amt > 250000) throw new HttpError(400, 'M-Pesa withdrawals are limited to KES 250,000 each.'); }
  else if (method === 'bank') { if (!/^[A-Za-z0-9 \-/,.]{6,60}$/.test(dest0)) throw new HttpError(400, 'Enter the bank name and account number.'); dest = dest0; }
  else throw new HttpError(400, 'Choose where to withdraw to.');
  require2fa(u, b.code);
  const amount = amt * 100, fee = method === 'mpesa' ? Math.max(3000, Math.round(amount * .01)) : 5000;
  const orig = crypto.randomUUID(), auto = method === 'mpesa' && B2C_ON && CFG.autoWithdrawMax > 0 && amt <= CFG.autoWithdrawMax;
  const w = tx(() => {
    const day = q("SELECT COALESCE(SUM(amount_cents),0) s FROM withdrawals WHERE user_id=? AND ts>? AND status NOT IN ('rejected','failed')").get(u.id, Date.now() - 864e5).s;
    if (day + amount > CFG.dailyWithdrawKes * 100) throw new HttpError(400, 'This is over your 24-hour withdrawal limit.');
    if (units(u.id, 'KES') < amount + fee) throw new HttpError(400, 'Not enough KES (the fee is added to the amount).');
    move(u.id, 'KES', -(amount + fee), 'withdraw', orig);
    const id = Number(q("INSERT INTO withdrawals(user_id,method,dest,amount_cents,fee_cents,status,orig_id,ts) VALUES(?,?,?,?,?,'pending',?,?)").run(u.id, method, dest, amount, fee, orig, Date.now()).lastInsertRowid);
    note(u.id, `Withdrawal of ${fmtKes(amount)} requested`);
    return q('SELECT * FROM withdrawals WHERE id=?').get(id);
  });
  if (auto) sendPayout(w).catch(e => log('payout_error', { id: w.id, err: e.message }));
  return { summary: `Withdrawal requested. Fee: ${fmtKes(fee)}. ` + (auto ? 'It is being sent now.' : 'It will be reviewed and sent shortly.') };
};
/* Daraja callbacks. They are unsigned, so: secret in the path, optional IP allowlist, and we re-check amounts / match our own records. */
function cbAuth(params, ip) {
  if (!MPESA_ON || !safeEq(params[0], CFG.mpCbSecret)) throw new HttpError(404, 'Not found');
  if (CFG.mpCbIps.length && !CFG.mpCbIps.includes(ip)) throw new HttpError(403, 'Forbidden');
}
const ACK = { ResultCode: 0, ResultDesc: 'Accepted' };
H['mpesa/stk'] = ({ b, params, ip }) => {
  cbAuth(params, ip);
  const cb = b && b.Body && b.Body.stkCallback; if (!cb) throw new HttpError(400, 'Bad payload');
  const d = q('SELECT * FROM deposits WHERE checkout_id=?').get(String(cb.CheckoutRequestID));
  if (!d) { log('stk_unknown_checkout', {}); return ACK; }
  if (Number(cb.ResultCode) === 0) {
    const items = (cb.CallbackMetadata && cb.CallbackMetadata.Item) || [], get = n => (items.find(i => i.Name === n) || {}).Value;
    const receipt = get('MpesaReceiptNumber'), paid = Math.round(Number(get('Amount')) * 100);
    if (!receipt || !Number.isFinite(paid)) { log('stk_bad_success_payload', { id: d.id }); return ACK; }
    try { settleDeposit(d, true, String(receipt), paid); } catch (e) { log('stk_settle_error', { id: d.id, err: e.message }); }
  } else settleDeposit(d, false);
  return ACK;
};
H['mpesa/b2c/result'] = ({ b, params, ip }) => {
  cbAuth(params, ip);
  const r = b && b.Result; if (!r) throw new HttpError(400, 'Bad payload');
  const w = q('SELECT * FROM withdrawals WHERE orig_id=?').get(String(r.OriginatorConversationID));
  if (!w) { log('b2c_unknown_result', {}); return ACK; }
  if (Number(r.ResultCode) === 0) {
    q("UPDATE withdrawals SET status='paid',receipt=? WHERE id=? AND status IN ('pending','processing')").run(String(r.TransactionID || ''), w.id);
    note(w.user_id, `Withdrawal of ${fmtKes(w.amount_cents)} sent via M-Pesa`);
  } else refundWithdrawal(w, 'failed', 'B2C result ' + r.ResultCode + ': ' + r.ResultDesc);
  return ACK;
};
H['mpesa/b2c/timeout'] = ({ b, params, ip }) => { cbAuth(params, ip); log('b2c_queue_timeout', {}); return ACK; }; // outcome unknown: leave for review

/* admin (bearer token; also put this behind your own IP allowlist) */
function adminAuth(req) {
  const t = (/^Bearer (.+)$/.exec(req.headers.authorization || '') || [])[1];
  if (!CFG.adminToken || !t || !safeEq(t, CFG.adminToken)) throw new HttpError(404, 'Not found');
}
H['admin/withdrawals'] = () => ({ withdrawals: q("SELECT id,user_id,method,dest,amount_cents,fee_cents,status,receipt,note,ts FROM withdrawals WHERE status IN ('pending','processing') ORDER BY id").all() });
H['admin/withdrawal'] = async ({ b, params }) => {
  const w = q('SELECT * FROM withdrawals WHERE id=?').get(Number(params[0])); if (!w) throw new HttpError(404, 'No such withdrawal.');
  const act = params[1];
  if (act === 'reject') { if (!refundWithdrawal(w, 'rejected', String(b.reason || 'rejected by admin'))) throw new HttpError(409, 'Already settled.'); return { ok: true }; }
  if (act === 'paid') { // for bank transfers (or M-Pesa sent by hand)
    const ch = q("UPDATE withdrawals SET status='paid',receipt=? WHERE id=? AND status IN ('pending','processing')").run(String(b.reference || 'manual'), w.id).changes;
    if (ch !== 1) throw new HttpError(409, 'Already settled.'); note(w.user_id, `Withdrawal of ${fmtKes(w.amount_cents)} sent`); return { ok: true };
  }
  if (act === 'approve') { if (w.method !== 'mpesa') throw new HttpError(400, 'Bank withdrawals are paid by hand, then marked paid.'); if (w.status !== 'pending') throw new HttpError(409, 'Not pending.'); await sendPayout(w); return { ok: true }; }
  throw new HttpError(400, 'Unknown action.');
};
H['admin/reconcile'] = async () => {
  const out = { customers: {}, house: {}, hedgesPending: q("SELECT COUNT(*) n FROM hedges WHERE status='pending'").get().n, batchesUnknown: q("SELECT COUNT(*) n FROM hedge_batches WHERE status='unknown'").get().n };
  q('SELECT asset,SUM(units) s FROM balances GROUP BY asset').all().forEach(r => out.customers[r.asset] = r.s / SCALE[r.asset]);
  q('SELECT asset,SUM(delta) s FROM ledger WHERE user_id=0 GROUP BY asset').all().forEach(r => out.house[r.asset] = r.s / SCALE[r.asset]);
  if (CFG.krKey && CFG.krSecret) { try { out.kraken = await krakenPrivate('Balance'); } catch (e) { out.krakenError = e.message; } }
  return out;
};

/* ---------- routing ---------- */
const routes = [];
const add = (method, re, fn, kind) => routes.push({ method, re: new RegExp('^/api/' + re + '$'), fn, kind });
['register', 'login', 'logout', '2fa/setup', '2fa/enable', '2fa/disable', 'trade', 'deposit/mpesa', 'withdraw'].forEach(p => add('POST', p, H[p] || H[p.split('/')[0]], 'user'));
add('GET', 'me', H.me, 'user'); add('GET', 'deposit/status/([\\w-]+)', H['deposit/status'], 'user');
add('POST', 'mpesa/callback/([\\w-]+)/stk', H['mpesa/stk'], 'cb');
add('POST', 'mpesa/b2c/([\\w-]+)/result', H['mpesa/b2c/result'], 'cb'); add('POST', 'mpesa/b2c/([\\w-]+)/timeout', H['mpesa/b2c/timeout'], 'cb');
add('GET', 'admin/withdrawals', H['admin/withdrawals'], 'admin'); add('GET', 'admin/reconcile', H['admin/reconcile'], 'admin');
add('POST', 'admin/withdrawals/(\\d+)/(approve|reject|paid)', H['admin/withdrawal'], 'admin');

function send(res, status, obj) { const s = JSON.stringify(obj); res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(s); }
function readBody(req) {
  return new Promise((ok, no) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > 65536) { no(new HttpError(413, 'Request too large.')); req.destroy(); } else ch.push(c); });
    req.on('end', () => { if (!ch.length) return ok({}); try { ok(JSON.parse(Buffer.concat(ch).toString())); } catch (_) { no(new HttpError(400, 'Bad request.')); } });
    req.on('error', no);
  });
}
const clientIp = req => CFG.trustProxy ? String((req.headers['x-forwarded-for'] || '').split(',').pop() || '').trim() || req.socket.remoteAddress : req.socket.remoteAddress;
const HEADERS = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
  ...(SECURE ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
};

async function handle(req, res) {
  Object.entries(HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  const url = new URL(req.url, 'http://x'), p = url.pathname, ip = clientIp(req);
  try {
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      const pg = [path.join(__dirname, 'public', 'index.html'), path.join(__dirname, 'index.html')].find(f => fs.existsSync(f));
      const html = fs.readFileSync(pg);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' }); return res.end(html);
    }
    if (p === '/healthz') return send(res, 200, { ok: true, pricesFresh: pricesPublic().fresh });
    if (req.method === 'GET' && p === '/api/prices') return send(res, 200, pricesPublic());
    if (req.method === 'GET' && p === '/api/stream') {
      if (clients.size > 2000) throw new HttpError(503, 'Busy.');
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
      res.write(`data: ${JSON.stringify(pricesPublic())}\n\n`); clients.add(res); req.on('close', () => clients.delete(res)); return;
    }
    const r = routes.map(x => ({ x, m: x.re.exec(p) })).find(o => o.m && o.x.method === req.method);
    if (!r) throw new HttpError(404, 'Not found');
    const { x, m } = r, params = m.slice(1);
    if (x.kind === 'admin') adminAuth(req);
    if (x.method === 'POST' && x.kind === 'user') {
      if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Unsupported request.');
      const o = req.headers.origin; if (o) { let h = ''; try { h = new URL(o).host; } catch (_) { } if (h !== req.headers.host) throw new HttpError(403, 'Forbidden'); }
    }
    const b = req.method === 'POST' ? await readBody(req) : {};
    const out = await x.fn({ req, res, b, u: x.kind === 'user' ? sessionUser(req) : null, params, ip });
    return send(res, 200, out);
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    log('unhandled', { path: p, err: e.stack || String(e) }); return send(res, 500, { error: 'Something went wrong. Try again.' });
  }
}

function start() {
  if (CFG.hedgeMode !== 'off' && !(CFG.krKey && CFG.krSecret)) throw new Error('HEDGE_MODE needs KRAKEN_KEY and KRAKEN_SECRET');
  if (!SECURE) log('warn', { msg: 'PUBLIC_URL is not https: cookies are not Secure and M-Pesa callbacks will not work' });
  log('config', { mpesa: MPESA_ON, b2c: B2C_ON, hedge: CFG.hedgeMode, admin: !!CFG.adminToken });
  pollPrices(); setInterval(pollPrices, 30000).unref();
  setInterval(hedgeRun, CFG.hedgeEveryMs).unref(); setInterval(() => sweepDeposits().catch(() => { }), 60000).unref();
  setInterval(() => { for (const c of clients) c.write(': ping\n\n'); }, 25000).unref();
  const srv = http.createServer(handle); srv.requestTimeout = 30000; srv.headersTimeout = 15000;
  srv.listen(CFG.port, () => log('listening', { port: CFG.port }));
  const bye = () => { srv.close(() => { db.close(); process.exit(0); }); setTimeout(() => process.exit(0), 5000).unref(); };
  process.on('SIGTERM', bye); process.on('SIGINT', bye);
  return srv;
}
if (require.main === module) start();
module.exports = { krakenSign, totp, checkTotp, b32enc, b32dec, tierOf };
