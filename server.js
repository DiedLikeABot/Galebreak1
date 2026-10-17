const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;
const ROOT = __dirname;
// serve whichever of these exists, so the folder can be laid out either way
const INDEX_CANDIDATES = ['/index.html', '/galebreak.html'];
function indexFile(){
  for(const f of INDEX_CANDIDATES){
    try { if (fs.existsSync(path.join(__dirname, f))) return f; } catch (e) {}
  }
  return INDEX_CANDIDATES[0];
}
const rooms = new Map();
const hosts = new Map();
const byCode = new Map();   // friend code -> player, for presence and invites

/* ===================== ACCOUNTS =====================
   A small JSON store. Passwords are salted and hashed with scrypt; the plain
   text is never written anywhere. Tokens let a client resume without sending
   the password again. Put this behind https, or the password crosses the wire
   in clear on the way in. */
/* Hosts like Render give a free service a fresh filesystem on every restart,
   so an accounts file written next to the code disappears and everyone is
   signed out. Point ACCOUNTS_PATH at a persistent disk to keep them. */
const ACCT_FILE = process.env.ACCOUNTS_PATH || path.join(ROOT, 'accounts.json');
let acctPersistent = true;
try {
  const dir = path.dirname(ACCT_FILE);
  fs.accessSync(dir, fs.constants.W_OK);
  acctPersistent = !!process.env.ACCOUNTS_PATH;
} catch (e) { acctPersistent = false; }
let accounts = {};
let acctDirty = false;

try {
  if (fs.existsSync(ACCT_FILE)) accounts = JSON.parse(fs.readFileSync(ACCT_FILE, 'utf8'));
} catch (e) { console.log('accounts.json unreadable, starting fresh'); }

function saveAccounts(){
  if (!acctDirty) return;
  acctDirty = false;
  const tmp = ACCT_FILE + '.tmp';
  try { fs.writeFileSync(tmp, JSON.stringify(accounts)); fs.renameSync(tmp, ACCT_FILE); }
  catch (e) { console.log('could not write accounts:', e.message); }
}
setInterval(saveAccounts, 4000);
process.on('SIGINT', () => { acctDirty = true; saveAccounts(); process.exit(0); });

function hashPass(pass, salt){ return crypto.scryptSync(String(pass), salt, 32).toString('hex'); }
function newCode(){
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let c;
  do { c = ''; for (let i = 0; i < 6; i++) c += A[crypto.randomInt(A.length)]; }
  while (Object.values(accounts).some(a => a.code === c));
  return c;
}
function accountByToken(tok){
  if (!tok) return null;
  for (const a of Object.values(accounts)) if (a.token === tok) return a;
  return null;
}
function authReply(ws, acct){
  send(ws, { type:'auth', ok:true, user:acct.user, token:acct.token,
             code:acct.code, profile:acct.profile || null });
}
/* The client sends its whole profile when it saves. Taken at face value that
   is an invitation to set your own spark balance, so it is treated as a
   request: the shape is rebuilt field by field, lists are capped, and the
   balance may fall freely (spending) but only rise by a plausible amount
   between saves. Anything bigger is clamped and logged. */
const MAX_COINS = 10000000;
const MAX_GAIN_PER_SAVE = 5000;        // a very good match pays a few hundred
function strArray(v, cap){
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const x of v) {
    if (typeof x !== 'string') continue;
    const t = x.slice(0, 40);
    if (t && out.indexOf(t) < 0) out.push(t);
    if (out.length >= cap) break;
  }
  return out;
}
function sanitizeProfile(inc, prev){
  prev = prev || {};
  const num = (v, lo, hi, dflt) => {
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(lo, Math.min(hi, Math.floor(n))) : dflt;
  };
  const out = {};
  const prevCoins = num(prev.coins, 0, MAX_COINS, 0);
  let coins = num(inc.coins, 0, MAX_COINS, prevCoins);
  if (coins > prevCoins + MAX_GAIN_PER_SAVE) {
    console.log('clamped a spark jump for', prev.user || 'account',
                prevCoins, '->', coins);
    coins = prevCoins + MAX_GAIN_PER_SAVE;
  }
  out.coins   = coins;
  out.xp      = Math.max(num(prev.xp,0,1e9,0), num(inc.xp, 0, 1e9, 0));
  out.matches = Math.max(num(prev.matches,0,1e7,0), num(inc.matches, 0, 1e7, 0));
  out.wins    = Math.max(num(prev.wins,0,1e7,0),    num(inc.wins, 0, 1e7, 0));
  out.kills   = Math.max(num(prev.kills,0,1e8,0),   num(inc.kills, 0, 1e8, 0));
  out.aimBest = num(inc.aimBest, 0, 1e6, num(prev.aimBest,0,1e6,0));

  out.owned = {};
  const inOwned = (inc.owned && typeof inc.owned === 'object') ? inc.owned : {};
  for (const cat of ['skin','face','pack','pick','glider','emote']) {
    out.owned[cat] = strArray(inOwned[cat], 400);
  }
  out.equipped = {};
  const inEq = (inc.equipped && typeof inc.equipped === 'object') ? inc.equipped : {};
  for (const cat of ['skin','face','pack','pick','glider','emote']) {
    const v = inEq[cat];
    out.equipped[cat] = (typeof v === 'string') ? v.slice(0,40) : '';
  }
  out.friends = strArray(inc.friends, 200);
  out.customItems = (inc.customItems && typeof inc.customItems === 'object')
    ? JSON.parse(JSON.stringify(inc.customItems).slice(0, 200000)) : (prev.customItems || {});
  if (Array.isArray(inc.maps)) {
    out.maps = inc.maps.slice(0, 24).map(mp => ({
      name: String(mp && mp.name || '').slice(0,24),
      code: String(mp && mp.code || '').slice(0, 20000),
      pieces: num(mp && mp.pieces, 0, 5000, 0),
      updated: num(mp && mp.updated, 0, 4e12, Date.now())
    }));
  } else out.maps = prev.maps || [];
  return out;
}

function validName(u){ return /^[A-Za-z0-9_.-]{3,16}$/.test(String(u || '')); }

/* ===================== PAYMENTS =====================
   Sparks are sold through Stripe Checkout. The browser never sees a card and
   never sees the secret key: it asks this server for a session, Stripe hosts
   the payment page, and Stripe calls back here afterwards. Sparks are only
   credited from that signed callback, never from anything the client says.

   Set these before any of it works:
     STRIPE_SECRET          sk_live_... or sk_test_...
     STRIPE_WEBHOOK_SECRET  whsec_...
     PUBLIC_URL             https://your-game-address  (for the return links)

   Read PAYMENTS.txt before switching this on. There are obligations that
   come with taking money that are not solved by code. */
/* Environment variable names are case sensitive, and getting that wrong is
   an easy way to spend an evening wondering why nothing works. Accept any
   reasonable spelling rather than being precious about it. */
function envAny(name){
  const tries = [name, name.toLowerCase(), name.toUpperCase(),
                 name.replace(/_/g,''), name.toLowerCase().replace(/_/g,'')];
  for (const t of tries) if (process.env[t]) return String(process.env[t]).trim();
  // last resort: a case-insensitive sweep of everything that is set
  const want = name.toLowerCase().replace(/_/g,'');
  for (const k in process.env)
    if (k.toLowerCase().replace(/_/g,'') === want && process.env[k])
      return String(process.env[k]).trim();
  return '';
}
const STRIPE_SECRET = envAny('STRIPE_SECRET');
const STRIPE_WEBHOOK_SECRET = envAny('STRIPE_WEBHOOK_SECRET');
const PUBLIC_URL = envAny('PUBLIC_URL').replace(/\/+$/,'');
const paymentsOn = () => !!(STRIPE_SECRET && STRIPE_WEBHOOK_SECRET && PUBLIC_URL);

// price in the smallest currency unit, so 99 is $0.99
const SPARK_PACKS = [
  { id:'s1', sparks:1000,  price:99,   label:'Handful of sparks' },
  { id:'s2', sparks:2800,  price:299,  label:'Pouch of sparks',  bonus:'12% extra' },
  { id:'s3', sparks:6200,  price:599,  label:'Crate of sparks',  bonus:'24% extra' },
  { id:'s4', sparks:13500, price:1199, label:'Vault of sparks',  bonus:'35% extra' }
];
const CURRENCY = envAny('CURRENCY') || 'usd';

/* Stripe turns Managed Payments on by default now, and it refuses any product
   without a tax code. Two ways out, and which you want depends on whether you
   want Stripe handling tax for you:
     - set STRIPE_TAX_CODE to a code from stripe.com/docs/tax/tax-codes and
       keep Managed Payments on, or
     - leave it unset and Managed Payments is switched off per session, which
       is the simpler path while testing.
   For in-game currency the usual choice is a digital goods or electronically
   supplied services code — check the list rather than taking my word for it,
   because the right code depends on what you sell and where you sell it. */
const STRIPE_TAX_CODE = envAny('STRIPE_TAX_CODE');

function stripeForm(obj, prefix, out){
  out = out || [];
  for (const k in obj) {
    const key = prefix ? prefix + '[' + k + ']' : k;
    const v = obj[k];
    if (v && typeof v === 'object') stripeForm(v, key, out);
    else out.push(encodeURIComponent(key) + '=' + encodeURIComponent(v));
  }
  return out;
}
async function stripeCall(path, body){
  const res = await fetch('https://api.stripe.com/v1/' + path, {
    method:'POST',
    headers:{ 'Authorization':'Bearer ' + STRIPE_SECRET,
              'Content-Type':'application/x-www-form-urlencoded' },
    body: stripeForm(body).join('&')
  });
  const json = await res.json();
  if (!res.ok) throw new Error((json.error && json.error.message) || ('Stripe said ' + res.status));
  return json;
}
async function createCheckout(acct, packId){
  const pack = SPARK_PACKS.find(p => p.id === packId);
  if (!pack) throw new Error('Unknown pack.');
  const body = {
    mode:'payment',
    success_url: PUBLIC_URL + '/?paid=1',
    cancel_url:  PUBLIC_URL + '/?paid=0',
    client_reference_id: acct.user,
    'line_items[0][quantity]': 1,
    'line_items[0][price_data][currency]': CURRENCY,
    'line_items[0][price_data][unit_amount]': pack.price,
    'line_items[0][price_data][product_data][name]':
      pack.sparks.toLocaleString() + ' sparks — GALEBREAK',
    'metadata[user]': acct.user,
    'metadata[pack]': pack.id,
    'metadata[sparks]': String(pack.sparks)
  };
  if (STRIPE_TAX_CODE) body['line_items[0][price_data][product_data][tax_code]'] = STRIPE_TAX_CODE;
  else body['managed_payments[enabled]'] = 'false';

  let session;
  try {
    session = await stripeCall('checkout/sessions', body);
  } catch (e) {
    // older accounts reject the managed_payments flag outright; retry without it
    if (/managed_payments/i.test(e.message) && body['managed_payments[enabled]']) {
      delete body['managed_payments[enabled]'];
      session = await stripeCall('checkout/sessions', body);
    } else throw e;
  }
  return session.url;
}
/* Stripe signs every webhook. An unsigned or mis-signed call is somebody
   trying to give themselves sparks, so it is rejected outright. */
function stripeSigValid(raw, header){
  if (!header) return false;
  const parts = {};
  header.split(',').forEach(kv => { const i = kv.indexOf('='); if (i>0) parts[kv.slice(0,i)] = kv.slice(i+1); });
  if (!parts.t || !parts.v1) return false;
  // reject anything older than five minutes, so a captured call cannot be replayed
  if (Math.abs(Date.now()/1000 - Number(parts.t)) > 300) return false;
  const expect = crypto.createHmac('sha256', STRIPE_WEBHOOK_SECRET)
                       .update(parts.t + '.' + raw).digest('hex');
  const a = Buffer.from(expect), b = Buffer.from(parts.v1);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
/* Kept on disk beside the accounts, because an in-memory set forgets every
   payment the moment the server restarts — and Stripe retries webhooks for
   days, so a restart at the wrong moment credits somebody twice. */
const PAID_FILE = process.env.PAID_PATH ||
  path.join(path.dirname(ACCT_FILE), 'paid-sessions.json');
let paidSessions = new Set();
try {
  if (fs.existsSync(PAID_FILE))
    paidSessions = new Set(JSON.parse(fs.readFileSync(PAID_FILE,'utf8')));
} catch(e){ console.log('could not read the payment log:', e.message); }
let paidDirty = false;
function rememberPaid(id){
  paidSessions.add(id);
  // keep the file from growing without bound
  if (paidSessions.size > 20000)
    paidSessions = new Set([...paidSessions].slice(-10000));
  paidDirty = true;
  flushPaid();
}
function flushPaid(){
  if (!paidDirty) return;
  try {
    fs.writeFileSync(PAID_FILE, JSON.stringify([...paidSessions]));
    paidDirty = false;
  } catch(e){ console.log('could not write the payment log:', e.message); }
}
function creditSparks(user, sparks, sessionId){
  if (paidSessions.has(sessionId)) {
    console.log('ignoring a repeat webhook for session', sessionId);
    return false;
  }
  // written before the sparks are granted, so a crash in between cannot
  // leave a payment looking uncredited and get replayed
  rememberPaid(sessionId);
  const a = accounts[String(user).toLowerCase()];
  if (!a) return false;
  a.profile = a.profile || {};
  a.profile.coins = (a.profile.coins || 0) + sparks;
  a.purchases = (a.purchases || 0) + 1;
  acctDirty = true;
  console.log('credited', sparks, 'sparks to', a.user);
  // tell them straight away if they are still connected
  for (const r of rooms.values())
    for (const p of r.values())
      if (p.acct === a) send(p.ws, { type:'sparks', coins:a.profile.coins, added:sparks });
  return true;
}

/* ===================== GOOGLE SIGN IN =====================
   Paste the OAuth client ID from Google Cloud below, or set GOOGLE_CLIENT_ID
   in the environment. Without it the button simply does not appear.
   The browser sends us a signed token; we check the signature against Google's
   published keys, and that it was issued for this client and has not expired.
   Nothing is trusted just because the browser said so. */
/* ===================== VOICE RELAY =====================
   STUN alone fails whenever both players are behind a symmetric NAT, which
   is most home routers paired with most phone networks. A TURN server
   relays the audio when a direct path cannot be found. Set these and voice
   works everywhere; leave them unset and it works only sometimes. */
/* YouTube live chat, if you give the server an API key. Twitch needs nothing
   and is handled entirely in the browser; Kick and TikTok have no usable
   public chat endpoint, so they are not offered rather than offered broken. */
const YOUTUBE_API_KEY = envAny('YOUTUBE_API_KEY');

/* ===================== YOUTUBE LIVE CHAT =====================
   Twitch can be read straight from the browser. YouTube cannot: it needs an
   API key, and a key in a web page is a key anyone can take and spend. So the
   server does the polling and passes the messages down to whoever is playing.

   Quota is the real constraint. A key gets 10,000 units a day. Finding your
   live broadcast costs 100, and each poll of the chat costs 5, so polling
   every six seconds burns roughly 3,000 an hour. That is about three hours of
   streaming per day. The poll respects YouTube's own suggested interval and
   stops when nobody is connected, which is most of what keeps it in budget. */
const yt = { chatId:null, videoId:null, page:null, timer:null,
             state:'off', note:'', nextAt:0, units:0, seen:new Set() };

async function ytApi(path, params){
  const q = new URLSearchParams(Object.assign({ key: YOUTUBE_API_KEY }, params));
  const res = await fetch('https://www.googleapis.com/youtube/v3/' + path + '?' + q);
  const body = await res.json();
  if (!res.ok) {
    const msg = (body.error && body.error.message) || ('HTTP ' + res.status);
    throw new Error(msg);
  }
  return body;
}
async function ytFindLive(){
  if (!YOUTUBE_CHANNEL_ID) throw new Error('No channel id set.');
  // 100 units, so this is done once and remembered
  const found = await ytApi('search', {
    part:'id', channelId:YOUTUBE_CHANNEL_ID, eventType:'live', type:'video', maxResults:1 });
  yt.units += 100;
  const item = (found.items || [])[0];
  if (!item) throw new Error('That channel is not live right now.');
  yt.videoId = item.id.videoId;
  const vid = await ytApi('videos', { part:'liveStreamingDetails', id:yt.videoId });
  yt.units += 1;
  const det = ((vid.items || [])[0] || {}).liveStreamingDetails || {};
  if (!det.activeLiveChatId) throw new Error('That broadcast has no live chat.');
  yt.chatId = det.activeLiveChatId;
  yt.page = null;
}
function ytViewers(){
  let n = 0;
  for (const r of rooms.values()) n += r.size;
  return n;
}
async function ytTick(){
  if (!YOUTUBE_API_KEY || !YOUTUBE_CHANNEL_ID) return;
  // nobody playing means nothing to send messages to, and quota is finite
  if (!ytViewers()) { yt.state = 'idle'; yt.note = 'Waiting for a player.'; return; }
  if (Date.now() < yt.nextAt) return;
  try {
    if (!yt.chatId) {
      yt.state = 'finding';
      await ytFindLive();
      yt.state = 'live';
      yt.note = 'Reading chat from your broadcast.';
      console.log('youtube chat attached to', yt.videoId);
    }
    const res = await ytApi('liveChat/messages', {
      liveChatId: yt.chatId, part:'snippet,authorDetails',
      maxResults: 200, pageToken: yt.page || '' });
    yt.units += 5;
    yt.page = res.nextPageToken || null;
    yt.nextAt = Date.now() + Math.max(5000, Number(res.pollingIntervalMillis) || 6000);

    const out = [];
    for (const it of (res.items || [])) {
      if (yt.seen.has(it.id)) continue;
      yt.seen.add(it.id);
      const sn = it.snippet || {}, au = it.authorDetails || {};
      const text = sn.displayMessage || (sn.textMessageDetails && sn.textMessageDetails.messageText);
      if (!text) continue;
      out.push({ user: au.displayName || 'viewer', text: String(text).slice(0,200),
                 mod: !!(au.isChatModerator || au.isChatOwner),
                 sub: !!au.isChatSponsor, src:'yt' });
    }
    if (yt.seen.size > 3000) yt.seen = new Set();
    if (out.length) {
      for (const r of rooms.values())
        for (const p of r.values()) send(p.ws, { type:'ytchat', items: out });
    }
  } catch (e) {
    yt.state = 'error';
    yt.note = e.message;
    yt.chatId = null;
    // a stream that has ended should be retried slowly, not hammered
    yt.nextAt = Date.now() + (/not live|no live chat/i.test(e.message) ? 120000 : 45000);
    console.log('youtube chat:', e.message);
  }
}
setInterval(() => { ytTick().catch(()=>{}); }, 3000);

const TURN_URL  = process.env.TURN_URL  || '';
const TURN_USER = process.env.TURN_USER || '';
const TURN_PASS = process.env.TURN_PASS || '';
function iceServers(){
  const list=[{ urls:['stun:stun.l.google.com:19302','stun:stun1.l.google.com:19302'] }];
  if(TURN_URL){
    list.push({ urls:TURN_URL.split(',').map(u=>u.trim()).filter(Boolean),
                username:TURN_USER, credential:TURN_PASS });
  }
  return list;
}

const GOOGLE_CLIENT_ID = (typeof envAny==='function' ? envAny('GOOGLE_CLIENT_ID') : '') ||
  '914423154502-mvm7kckhmu1gcgutv3quutej92pnvpf5.apps.googleusercontent.com';

/* ===================== EXCLUSIVE REWARDS =====================
   Granted here, never by the client, so a player cannot edit their own save
   into owning one. Two routes: a code you hand out, or a real check against
   YouTube to see whether the signed-in account subscribes to your channel. */
const YOUTUBE_CHANNEL_ID = process.env.YOUTUBE_CHANNEL_ID || 'UCyf9HIpnQT9Z6ZbWx6a5y_g';

// Change these, add as many as you like. Codes are case insensitive.
const REDEEM_CODES = {
  'ILIKECHEESEMODLY': { cat:'skin', id:'subscriber', name:'Signal Breaker' }
};

function grant(acct, reward){
  acct.profile = acct.profile || {};
  acct.profile.owned = acct.profile.owned || {};
  const list = acct.profile.owned[reward.cat] = acct.profile.owned[reward.cat] || [];
  if (!list.includes(reward.id)) list.push(reward.id);
  acctDirty = true;
}

async function isSubscribed(accessToken){
  if (!YOUTUBE_CHANNEL_ID) throw new Error('No channel is configured on this server.');
  const url = 'https://www.googleapis.com/youtube/v3/subscriptions' +
              '?part=snippet&mine=true&forChannelId=' + encodeURIComponent(YOUTUBE_CHANNEL_ID);
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + accessToken } });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error('YouTube refused the request (' + res.status + '). ' + detail.slice(0, 120));
  }
  const body = await res.json();
  return Array.isArray(body.items) && body.items.length > 0;
}

let jwks = { keys: [], at: 0 };
async function googleKeys(force){
  const fresh = Date.now() - jwks.at < 3600e3;
  if (!force && fresh && jwks.keys.length) return jwks.keys;
  const res = await fetch('https://www.googleapis.com/oauth2/v3/certs');
  const body = await res.json();
  jwks = { keys: body.keys || [], at: Date.now() };
  return jwks.keys;
}
function b64urlToBuf(str){
  return Buffer.from(String(str).replace(/-/g,'+').replace(/_/g,'/'), 'base64');
}
async function verifyGoogleToken(idToken){
  if (!GOOGLE_CLIENT_ID) throw new Error('Google sign in is not configured on this server.');
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed token.');

  const header  = JSON.parse(b64urlToBuf(parts[0]).toString('utf8'));
  const payload = JSON.parse(b64urlToBuf(parts[1]).toString('utf8'));
  if (header.alg !== 'RS256') throw new Error('Unexpected signing algorithm.');

  let keys = await googleKeys(false);
  let jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) { keys = await googleKeys(true); jwk = keys.find(k => k.kid === header.kid); }
  if (!jwk) throw new Error('Signing key not recognised.');

  const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = crypto.createVerify('RSA-SHA256')
    .update(parts[0] + '.' + parts[1])
    .verify(pub, b64urlToBuf(parts[2]));
  if (!ok) throw new Error('Signature did not verify.');

  const iss = payload.iss;
  if (iss !== 'accounts.google.com' && iss !== 'https://accounts.google.com')
    throw new Error('Wrong issuer.');
  if (payload.aud !== GOOGLE_CLIENT_ID) throw new Error('Token was issued for another app.');
  if (!payload.exp || payload.exp * 1000 < Date.now()) throw new Error('Token has expired.');
  if (!payload.sub) throw new Error('Token has no subject.');
  return payload;
}
function accountForGoogle(pay){
  for (const a of Object.values(accounts)) if (a.googleId === pay.sub) return a;
  let base = String(pay.name || (pay.email || '').split('@')[0] || 'player')
    .replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 12) || 'player';
  if (base.length < 3) base = base + 'xyz'.slice(0, 3 - base.length);
  let user = base, n = 1;
  while (accounts[user.toLowerCase()]) user = base + (++n);
  const a = { user, googleId: pay.sub, email: pay.email || '',
              token: crypto.randomUUID(), code: newCode(),
              profile: null, created: Date.now() };
  accounts[user.toLowerCase()] = a;
  acctDirty = true;
  console.log('google account created:', user);
  return a;
}

function findById(id){
  for(const r of rooms.values()){ const p = r.get(id); if(p) return p; }
  return null;
}   // room name -> player id that simulates the bots

// how many people fit in one match of each mode
const CAP = { BR:20, TN:40, ZW:12, BX:2 };
function capFor(room){
  const m = /-(BR|TN|ZW|BX)(?:-\d+)?$/.exec(room || '');
  return (m && CAP[m[1]]) || 20;
}
// find a public room of this mode with a free seat, or open the next one
function quickRoom(mode){
  const tag = String(mode || 'BR').toUpperCase().slice(0,2);
  const cap = CAP[tag] || 20;
  for (let i = 1; i < 200; i++) {
    const name = 'PUBLIC-' + tag + '-' + i;
    const r = rooms.get(name);
    if (!r || r.size < cap) return name;
  }
  return 'PUBLIC-' + tag + '-1';
}
function totalOnline(){
  let n = 0;
  for (const r of rooms.values()) n += r.size;
  return n;
}
function broadcastOnline(){
  const n = totalOnline();
  for (const r of rooms.values())
    for (const p of r.values()) send(p.ws, { type:'online', total:n, room:p.room, inRoom:r.size });
}

// One client in each room owns the bots. Everyone else just renders what it sends.
function assignHost(roomName, r){
  const current = hosts.get(roomName);
  if(current && r.has(current)) return current;
  const next = r.size ? [...r.keys()][0] : null;
  if(next) hosts.set(roomName, next); else hosts.delete(roomName);
  if(next) broadcast(r, { type:'host', id:next });
  return next;
}

function room(name){
  if(!rooms.has(name)) rooms.set(name, new Map());
  return rooms.get(name);
}
function send(ws, msg){
  if(ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}
function broadcast(r, msg, except){
  for(const p of r.values()) if(p.ws !== except) send(p.ws, msg);
}
function publicPlayer(p){
  return { id:p.id, name:p.name, party:p.party, skin:p.skin, code:p.code, x:p.x, y:p.y, z:p.z, yaw:p.yaw, pitch:p.pitch,
           phase:p.phase, hp:p.hp, shield:p.shield, slot:p.slot, weapon:p.weapon,
           alive:p.alive, cheats:p.cheats || [] };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  // Stripe calls this when a payment completes
  if(req.method === 'POST' && u.pathname === '/api/stripe-webhook'){
    let raw = '';
    req.on('data', c => { raw += c; if (raw.length > 1e6) req.destroy(); });
    req.on('end', () => {
      if(!paymentsOn()){ res.writeHead(503); return res.end('payments off'); }
      if(!stripeSigValid(raw, req.headers['stripe-signature'])){
        console.log('rejected a webhook with a bad signature');
        res.writeHead(400); return res.end('bad signature');
      }
      let ev;
      try { ev = JSON.parse(raw); } catch(e){ res.writeHead(400); return res.end('bad json'); }
      if(ev.type === 'checkout.session.completed'){
        const o = ev.data.object;
        const sparks = Number((o.metadata && o.metadata.sparks) || 0);
        const user = (o.metadata && o.metadata.user) || o.client_reference_id;
        if(sparks > 0 && user) creditSparks(user, sparks, o.id);
      }
      res.writeHead(200); res.end('ok');
    });
    return;
  }

  if(u.pathname === '/health' || u.pathname === '/status'){
    const list = [];
    for(const [name, r] of rooms) list.push({ room:name, players:r.size, cap:capFor(name) });
    res.writeHead(200, { 'Content-Type':'application/json', 'Access-Control-Allow-Origin':'*' });
    return res.end(JSON.stringify({ ok:true, online: totalOnline(),
      accounts: Object.keys(accounts).length, rooms: list }));
  }
  /* Serving whatever is asked for out of the application directory means
     accounts.json, server.js and anything else sitting there is one URL away.
     Only these extensions are public, and a few names are never served no
     matter what. */
  const PUBLIC_EXT = new Set(['.html','.js','.css','.png','.jpg','.jpeg','.gif','.svg',
                              '.webp','.ico','.mp4','.webm','.woff','.woff2','.ttf','.txt']);
  const NEVER = new Set(['accounts.json','server.js','package.json','package-lock.json',
                         '.env','payments.json','.git']);
  const file = u.pathname === '/' ? indexFile() : u.pathname;
  const safe = path.normalize(file).replace(/^(\.\.[\/\\])+/, '');
  const full = path.join(ROOT, safe);
  if(!full.startsWith(ROOT)){ res.writeHead(403); return res.end('Forbidden'); }
  const base = path.basename(full).toLowerCase();
  const ext = path.extname(full).toLowerCase();
  if(NEVER.has(base) || base.startsWith('.') || !PUBLIC_EXT.has(ext)){
    res.writeHead(404, { 'Content-Type':'text/plain' });
    return res.end('Not found');
  }
  fs.readFile(full, (err, data) => {
    if(err){
      res.writeHead(404, { 'Content-Type':'text/html' });
      if(u.pathname === '/'){
        return res.end('<body style="background:#0a0e16;color:#dbe6f2;font-family:system-ui;'+
          'padding:40px;line-height:1.6"><h2>The game file is missing</h2>'+
          '<p>The server is running, but there is no <b>index.html</b> next to '+
          '<b>server.js</b>. Upload it to the same folder and redeploy.</p></body>');
      }
      return res.end('Not found');
    }
    const ext = path.extname(full);
    const type = ext === '.html' ? 'text/html'
               : ext === '.js'   ? 'text/javascript'
               : ext === '.css'  ? 'text/css'
               : 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store',
             'Access-Control-Allow-Origin': '*' });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  const p = { ws, id: crypto.randomUUID().slice(0,8), name:'Player', room:null, party:null, cheats:[], skin:'recruit', code:null, voice:false,
              x:0, y:0, z:0, yaw:0, pitch:0, phase:'bus',
              hp:100, shield:0, slot:0, weapon:null, alive:true, lastHit:0 };

  send(ws, { type:'config', server:'galebreak-2', accounts:true,
             persistent: acctPersistent,
             ice: iceServers(),
             turn: !!TURN_URL,
             ytChat: !!(YOUTUBE_API_KEY && YOUTUBE_CHANNEL_ID),
             ytState: yt.state, ytNote: yt.note,
             codeCount: Object.keys(REDEEM_CODES).length,
             payments: paymentsOn(),
             packs: paymentsOn() ? SPARK_PACKS : null,
             currency: CURRENCY,
             googleClientId: GOOGLE_CLIENT_ID || null,
             youtube: YOUTUBE_CHANNEL_ID || null });

  ws.on('message', (buf) => {
    let m;
    try { m = JSON.parse(buf); } catch { return; }

    /* ---------- accounts ---------- */
    if (m.type === 'register' || m.type === 'login') {
      p.authTries = (p.authTries || 0) + 1;
      if (p.authTries > 12) return send(ws, { type:'auth', ok:false, error:'Too many attempts.' });
      const user = String(m.user || '').trim();
      const pass = String(m.pass || '');
      if (!validName(user))
        return send(ws, { type:'auth', ok:false, error:'3 to 16 letters, numbers, _ . or -' });
      if (pass.length < 6)
        return send(ws, { type:'auth', ok:false, error:'Password needs at least 6 characters.' });
      const key = user.toLowerCase();

      if (m.type === 'register') {
        if (accounts[key]) return send(ws, { type:'auth', ok:false, error:'That name is taken.' });
        const salt = crypto.randomBytes(16).toString('hex');
        accounts[key] = { user, salt, hash:hashPass(pass, salt),
                          token:crypto.randomUUID(), code:newCode(),
                          profile:m.profile || null, created:Date.now() };
        acctDirty = true;
        p.acct = accounts[key]; p.name = user; p.code = accounts[key].code;
        byCode.set(p.code, p);
        console.log('registered', user);
        return authReply(ws, accounts[key]);
      }

      const a = accounts[key];
      if (!a) return send(ws, { type:'auth', ok:false, error:'No such account.' });
      const tryHash = Buffer.from(hashPass(pass, a.salt), 'hex');
      const realHash = Buffer.from(a.hash, 'hex');
      if (tryHash.length !== realHash.length || !crypto.timingSafeEqual(tryHash, realHash))
        return send(ws, { type:'auth', ok:false, error:'Wrong password.' });
      a.token = a.token || crypto.randomUUID();
      if (!a.code) { a.code = newCode(); acctDirty = true; }
      p.acct = a; p.name = a.user; p.code = a.code;
      byCode.set(p.code, p);
      console.log('login', a.user);
      return authReply(ws, a);
    }

    if (m.type === 'google') {
      verifyGoogleToken(m.credential).then(pay => {
        const a = accountForGoogle(pay);
        a.token = a.token || crypto.randomUUID();
        if (!a.code) { a.code = newCode(); acctDirty = true; }
        p.acct = a; p.name = a.user; p.code = a.code;
        byCode.set(p.code, p);
        console.log('google login', a.user);
        authReply(ws, a);
      }).catch(err => {
        send(ws, { type:'auth', ok:false, error: 'Google sign in failed: ' + err.message });
      });
      return;
    }

    if (m.type === 'rename') {
      if (!p.acct) return send(ws, { type:'rename', ok:false, error:'Sign in first.' });
      const want = String(m.name || '').trim();
      if (!validName(want))
        return send(ws, { type:'rename', ok:false, error:'3 to 16 letters, numbers, _ . or -' });
      const key = want.toLowerCase(), oldKey = p.acct.user.toLowerCase();
      if (key !== oldKey && accounts[key])
        return send(ws, { type:'rename', ok:false, error:'That name is taken.' });
      const since = Date.now() - (p.acct.renamedAt || 0);
      if (p.acct.renamedAt && since < 86400000)
        return send(ws, { type:'rename', ok:false,
          error:'You can change your name again in ' +
                Math.ceil((86400000 - since)/3600000) + ' hours.' });
      const acct = p.acct;
      delete accounts[oldKey];
      acct.user = want;
      acct.renamedAt = Date.now();
      accounts[key] = acct;
      acctDirty = true;
      p.name = want;
      broadcast(rooms.get(p.room) || new Map(), { type:'player_name', id:p.id, name:want });
      console.log('rename', oldKey, '->', want);
      return send(ws, { type:'rename', ok:true, user:want });
    }

    if (m.type === 'buy') {
      if (!p.acct) return send(ws, { type:'buy', ok:false, error:'Sign in first.' });
      if (!paymentsOn())
        return send(ws, { type:'buy', ok:false,
          error:'Buying sparks is not set up on this server.' });
      createCheckout(p.acct, String(m.pack || ''))
        .then(url => send(ws, { type:'buy', ok:true, url }))
        .catch(e => send(ws, { type:'buy', ok:false, error:e.message }));
      return;
    }

    if (m.type === 'redeem') {
      if (!p.acct) return send(ws, { type:'reward', ok:false,
        error:'You are not signed in. Open the ACCOUNT tab and sign in first.' });
      p.redeemTries = (p.redeemTries || 0) + 1;
      if (p.redeemTries > 20) return send(ws, { type:'reward', ok:false, error:'Too many attempts.' });
      const code = String(m.code || '').trim().toUpperCase();
      const reward = REDEEM_CODES[code];
      if (!reward) return send(ws, { type:'reward', ok:false, known:Object.keys(REDEEM_CODES).length,
        error:'That code is not valid on this server.' });
      grant(p.acct, reward);
      console.log('redeemed', code, 'for', p.acct.user);
      return send(ws, Object.assign({ type:'reward', ok:true }, reward));
    }

    if (m.type === 'ytcheck') {
      if (!p.acct) return send(ws, { type:'reward', ok:false, error:'Sign in first.' });
      isSubscribed(String(m.token || '')).then(sub => {
        if (!sub) {
          return send(ws, { type:'reward', ok:false,
            error:'That account is not subscribed yet. Subscribe, then try again.' });
        }
        const reward = { cat:'skin', id:'subscriber', name:'Signal Breaker' };
        grant(p.acct, reward);
        console.log('subscriber verified:', p.acct.user);
        send(ws, Object.assign({ type:'reward', ok:true }, reward));
      }).catch(err => {
        send(ws, { type:'reward', ok:false, error: err.message });
      });
      return;
    }

    if (m.type === 'ping') {
      return send(ws, { type:'pong', t:m.t });
    }

    if (m.type === 'resume') {
      const a = accountByToken(m.token);
      if (!a) return send(ws, { type:'auth', ok:false, error:'Session expired.' });
      p.acct = a; p.name = a.user; p.code = a.code;
      byCode.set(p.code, p);
      return authReply(ws, a);
    }

    if (m.type === 'saveProfile') {
      if (!p.acct || !m.profile) return;
      p.acct.profile = sanitizeProfile(m.profile, p.acct.profile);
      acctDirty = true;
      return;
    }

    if (m.type === 'logout') {
      if (p.acct) { p.acct.token = crypto.randomUUID(); acctDirty = true; }
      p.acct = null;
      return send(ws, { type:'auth', ok:false, error:'Signed out.' });
    }

    if(m.type === 'quickplay'){
      if(p.room) return;
      m = Object.assign({}, m, { type:'join', room: quickRoom(m.mode) });
    }

    if(m.type === 'join'){
      if(p.room) return;
      p.name = p.acct ? p.acct.user : String(m.name || 'Player').slice(0,16);
      p.room = String(m.room || 'MAIN').toUpperCase().slice(0,12);
      p.party = m.party ? String(m.party).toUpperCase().slice(0,12) : null;
      if(m.skin) p.skin = String(m.skin).slice(0,20);
      if(!p.acct && m.code) p.code = String(m.code).toUpperCase().slice(0,12);
      if(p.code) byCode.set(p.code, p);
      const r = room(p.room);
      r.set(p.id, p);
      send(ws, { type:'welcome', id:p.id, room:p.room,
                 players:[...r.values()].filter(x => x !== p).map(publicPlayer) });
      broadcast(r, Object.assign({ type:'player_join' }, publicPlayer(p)), ws);
      broadcast(r, { type:'count', count:r.size, cap:capFor(p.room) });
      broadcastOnline();
      const h = assignHost(p.room, r);
      send(ws, { type:'host', id:h });
      if(h !== p.id){
        const hp = r.get(h);
        if(hp) send(hp.ws, { type:'botreq' });   // new arrival needs the bot roster
      }
      console.log(`${p.name} joined room ${p.room} (${r.size} in room)`);
      return;
    }

    if(!p.room) return;
    const r = rooms.get(p.room);
    if(!r) return;

    if(m.type === 'setparty'){
      const want = m.party ? String(m.party).toUpperCase().slice(0,12) : null;
      // a duo is two people; joining a full squad has to be refused somewhere
      if (want && want !== p.party) {
        const size = Math.max(1, Math.min(4, Number(m.size) || 4));
        let inSquad = 0;
        for (const q of r.values()) if (q !== p && q.party === want) inSquad++;
        if (inSquad >= size) return send(ws, { type:'partyFull', party:want, size });
      }
      p.party = want;
      broadcast(r, { type:'player_party', id:p.id, party:p.party, name:p.name });
      send(ws, { type:'player_party', id:p.id, party:p.party, name:p.name });
      console.log(`${p.name} squad -> ${p.party || 'none'}`);
      return;
    }

    if(m.type === 'state'){
      p.x = Number(m.x)||0; p.y = Number(m.y)||0; p.z = Number(m.z)||0;
      p.yaw = Number(m.yaw)||0; p.pitch = Number(m.pitch)||0;
      p.phase = String(m.phase || 'ground');
      p.hp = Math.max(0, Math.min(100, Number(m.hp)||0));
      p.shield = Math.max(0, Math.min(100, Number(m.shield)||0));
      p.slot = Number(m.slot)||0;
      p.weapon = m.weapon || null;
      if(m.skin) p.skin = String(m.skin).slice(0,20);
      p.alive = p.hp > 0 && m.alive !== false;
      broadcast(r, Object.assign({ type:'state' }, publicPlayer(p)), ws);

    } else if(m.type === 'shot'){
      broadcast(r, { type:'shot', id:p.id, origin:m.origin, end:m.end }, ws);

    } else if(m.type === 'hit'){
      const t = r.get(String(m.target || ''));
      if(!t || !t.alive || t.id === p.id) return;
      const now = Date.now();

      /* The client reports its own hits, so the server checks whether each
         one could have happened: both players alive and on the ground, within
         the range of the longest weapon in the game, not on the same squad,
         and not arriving faster than any weapon can fire. None of this makes
         the client trustworthy — that needs server-side simulation — but it
         turns "any damage to anyone" into "plausible damage to someone you
         could actually see". */
      if(p.phase !== 'ground' || t.phase !== 'ground') return;
      if(p.party && t.party && p.party === t.party) return;   // same squad

      const dx = (p.x||0)-(t.x||0), dy = (p.y||0)-(t.y||0), dz = (p.z||0)-(t.z||0);
      const dist = Math.sqrt(dx*dx + dy*dy + dz*dz);
      const MAX_RANGE = 150;                 // the sniper, plus a margin
      if(dist > MAX_RANGE){
        p.badHits = (p.badHits||0)+1;
        if(p.badHits === 20) console.log('implausible hit distances from', p.name);
        return;
      }

      // a burst allowance, so a fast weapon is fine but a stream of hits is not
      p.hitBucket = Math.min(6, (p.hitBucket===undefined?6:p.hitBucket) +
                                (now - (p.lastHit||now))/120);
      if(p.hitBucket < 1){ return; }
      p.hitBucket -= 1;
      p.lastHit = now;

      const asName = m.asName ? String(m.asName).slice(0,16) : null;
      // no weapon in the game does more than this, even to the head
      let dmg = Math.max(0, Math.min(130, Number(m.dmg)||0));
      if(dist > 60) dmg = Math.min(dmg, 110);      // falloff at distance
      const shield = Math.min(t.shield, dmg);
      t.shield -= shield; dmg -= shield;
      t.hp = Math.max(0, t.hp - dmg);
      t.alive = t.hp > 0;
      broadcast(r, { type:'damage', target:t.id, shooter:p.id, shooterName:asName || p.name,
                     byBot:!!asName, hp:t.hp, shield:t.shield, killed:!t.alive }, null);
      if(!t.alive) console.log(`${asName || p.name} eliminated ${t.name}`);

    } else if(m.type === 'bots' || m.type === 'botinit' || m.type === 'botkill' || m.type === 'storm'){
      // only the room's host is allowed to describe the bots
      if(hosts.get(p.room) !== p.id) return;
      broadcast(r, Object.assign({}, m), ws);

    } else if(m.type === 'botreq'){
      const h = r.get(hosts.get(p.room));
      if(h) send(h.ws, { type:'botreq' });

    } else if(m.type === 'chat'){
      const text = String(m.text || '').slice(0, 200).replace(/[\r\n]/g, ' ');
      if(!text.trim()) return;
      const now = Date.now();
      if(now - (p.lastChat || 0) < 400) return;      // simple flood guard
      p.lastChat = now;
      const scope = m.scope === 'team' ? 'team' : 'all';
      for(const q of r.values()){
        if(scope === 'team' && (!p.party || q.party !== p.party)) continue;
        send(q.ws, { type:'chat', from:p.name, id:p.id, scope, text,
                     party:p.party, mine:q.id === p.id });
      }

    } else if(m.type === 'presence'){
      const codes = Array.isArray(m.codes) ? m.codes.slice(0, 50) : [];
      const list = codes.map(c => {
        const t = byCode.get(String(c).toUpperCase());
        return t ? { code:t.code, online:true, name:t.name, room:t.room }
                 : { code:String(c).toUpperCase(), online:false };
      });
      send(ws, { type:'presence', list });

    } else if(m.type === 'invite'){
      const t = byCode.get(String(m.code || '').toUpperCase());
      if(!t) return send(ws, { type:'inviteFail', code:m.code });
      send(t.ws, { type:'invite', from:p.name, code:p.code, room:p.room, party:p.party || null });
      send(ws, { type:'inviteSent', name:t.name });

    } else if(m.type === 'rtc'){
      // voice chat signalling: pass the blob through to one person in the room
      const t = r.get(String(m.to || ''));
      if(t) send(t.ws, { type:'rtc', from:p.id, name:p.name, data:m.data });

    } else if(m.type === 'voice'){
      p.voice = !!m.on;
      broadcast(r, { type:'voice', id:p.id, on:p.voice }, ws);

    } else if(m.type === 'cheat'){
      p.cheats = Array.isArray(m.list) ? m.list.slice(0,8).map(x => String(x).slice(0,12)) : [];
      broadcast(r, { type:'cheat', id:p.id, name:p.name, list:p.cheats });

    } else if(m.type === 'emote'){
      broadcast(r, { type:'emote', id:p.id, e:m.e ? String(m.e).slice(0,16) : null }, ws);

    } else if(m.type === 'build'){
      broadcast(r, { type:'build', owner:p.id,
        x:Number(m.x)||0, y:Number(m.y)||0, z:Number(m.z)||0,
        w:Number(m.w)||4, h:Number(m.h)||0.35, d:Number(m.d)||4,
        rx:Number(m.rx)||0, ry:Number(m.ry)||0, rz:Number(m.rz)||0 }, ws);
    }
  });

  ws.on('close', () => {
    if(!p.room) return;
    const r = rooms.get(p.room);
    if(!r) return;
    r.delete(p.id);
    if(p.code && byCode.get(p.code) === p) byCode.delete(p.code);
    broadcast(r, { type:'player_leave', id:p.id });
    broadcast(r, { type:'count', count:r.size, cap:capFor(p.room) });
    broadcastOnline();
    if(hosts.get(p.room) === p.id){
      hosts.delete(p.room);
      const h = assignHost(p.room, r);
      if(h) console.log(`host of ${p.room} moved to ${h}`);
    }
    if(r.size === 0){ rooms.delete(p.room); hosts.delete(p.room); }
    console.log(`${p.name} left room ${p.room}`);
  });
});

server.listen(PORT, () => {
  console.log(`GALEBREAK server running: http://localhost:${PORT}`);
  console.log(`  version galebreak-2 · accounts on · google sign in ${GOOGLE_CLIENT_ID?'configured':'not configured'}`);
  console.log(`  subscriber check ${YOUTUBE_CHANNEL_ID?'configured':'off'} · redeem codes: ${Object.keys(REDEEM_CODES).join(', ')}`);
  console.log(`  payments ${paymentsOn()?'configured':'off'}` +
    (paymentsOn() ? (STRIPE_TAX_CODE ? '  [tax code set]' : '  [managed payments off]') : '') +
    (paymentsOn() ? '' :
      '  [secret:' + (STRIPE_SECRET?'yes':'MISSING') +
      ' webhook:' + (STRIPE_WEBHOOK_SECRET?'yes':'MISSING') +
      ' url:' + (PUBLIC_URL?'yes':'MISSING') + ']'));
  console.log(`  accounts file: ${ACCT_FILE}`);
  console.log(`  voice relay: ${TURN_URL ? 'TURN configured' : 'STUN only — voice will fail behind strict NATs'}`);
  console.log(`  youtube chat: ${
    (YOUTUBE_API_KEY && YOUTUBE_CHANNEL_ID) ? 'ready, polls while people are playing'
    : (YOUTUBE_API_KEY ? 'key set but no channel id' : 'not configured (Twitch needs no key)')}`);
  if (!acctPersistent) {
    console.log('  WARNING: that path is not a persistent disk. On a host that');
    console.log('  resets its filesystem, accounts will be lost on every restart.');
    console.log('  Set ACCOUNTS_PATH to a mounted disk to keep them.');
  }
  console.log(`Other computers on your network: http://<this-machine-ip>:${PORT}`);
});
