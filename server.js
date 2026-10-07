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
const ACCT_FILE = path.join(ROOT, 'accounts.json');
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
function validName(u){ return /^[A-Za-z0-9_.-]{3,16}$/.test(String(u || '')); }

/* ===================== GOOGLE SIGN IN =====================
   Paste the OAuth client ID from Google Cloud below, or set GOOGLE_CLIENT_ID
   in the environment. Without it the button simply does not appear.
   The browser sends us a signed token; we check the signature against Google's
   published keys, and that it was issued for this client and has not expired.
   Nothing is trusted just because the browser said so. */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID ||
  '914423154502-mvm7kckhmu1gcgutv3quutej92pnvpf5.apps.googleusercontent.com';

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
  if(u.pathname === '/health' || u.pathname === '/status'){
    const list = [];
    for(const [name, r] of rooms) list.push({ room:name, players:r.size, cap:capFor(name) });
    res.writeHead(200, { 'Content-Type':'application/json', 'Access-Control-Allow-Origin':'*' });
    return res.end(JSON.stringify({ ok:true, online: totalOnline(),
      accounts: Object.keys(accounts).length, rooms: list }));
  }
  const file = u.pathname === '/' ? indexFile() : u.pathname;
  const safe = path.normalize(file).replace(/^(\.\.[\/\\])+/, '');
  const full = path.join(ROOT, safe);
  if(!full.startsWith(ROOT)){ res.writeHead(403); return res.end('Forbidden'); }
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
             googleClientId: GOOGLE_CLIENT_ID || null });

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

    if (m.type === 'resume') {
      const a = accountByToken(m.token);
      if (!a) return send(ws, { type:'auth', ok:false, error:'Session expired.' });
      p.acct = a; p.name = a.user; p.code = a.code;
      byCode.set(p.code, p);
      return authReply(ws, a);
    }

    if (m.type === 'saveProfile') {
      if (!p.acct || !m.profile) return;
      p.acct.profile = m.profile; acctDirty = true;
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
      p.party = m.party ? String(m.party).toUpperCase().slice(0,12) : null;
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
      if(now - p.lastHit < 35) return;   // crude rate limit
      p.lastHit = now;
      const asName = m.asName ? String(m.asName).slice(0,16) : null;
      let dmg = Math.max(0, Math.min(250, Number(m.dmg)||0));
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
      send(t.ws, { type:'invite', from:p.name, code:p.code, room:p.room });
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
  console.log(`Other computers on your network: http://<this-machine-ip>:${PORT}`);
});
