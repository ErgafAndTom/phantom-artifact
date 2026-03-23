const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.set('trust proxy', true); // Render / Railway за reverse proxy

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.raw({ type: '*/*', limit: '10mb' }));

const LOG_DIR = process.env.LOG_DIR || '.';
const LOG_FILE = path.join(LOG_DIR, 'phantom.log');
const MAX_LOG_SIZE = 5 * 1024 * 1024; // 5MB — ротация
const PORT = process.env.PORT || 3000;
const PHANTOM_DOMAIN = process.env.PHANTOM_DOMAIN || 'localhost';

// ─── Log rotation ───
function rotateLogIfNeeded() {
    try {
        const stats = fs.statSync(LOG_FILE);
        if (stats.size > MAX_LOG_SIZE) {
            const rotated = LOG_FILE + '.' + Date.now();
            fs.renameSync(LOG_FILE, rotated);
            // Удаляем старые ротированные логи (оставляем 3)
            const dir = path.dirname(LOG_FILE);
            const base = path.basename(LOG_FILE);
            const rotatedFiles = fs.readdirSync(dir)
                .filter(f => f.startsWith(base + '.'))
                .sort()
                .reverse();
            rotatedFiles.slice(3).forEach(f => fs.unlinkSync(path.join(dir, f)));
        }
    } catch {}
}

// ─── Middleware: логируем ВСЁ ───
app.use((req, res, next) => {
    const entry = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        query: req.query,
        headers: {
            'user-agent': req.headers['user-agent'],
            'content-type': req.headers['content-type'],
            'authorization': req.headers['authorization'] ? '[PRESENT]' : null,
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'origin': req.headers['origin'],
            'referer': req.headers['referer']
        },
        body: typeof req.body === 'object' ? req.body : req.body?.toString?.(),
        ip: req.ip
    };

    rotateLogIfNeeded();
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
    req.phantomId = entry.id;
    next();
});

// ─── PHANTOM AUTH: ничейные креденшалы, проходящие любую валидацию ───
//
// Идея: логин "1" / пароль "1" — но сервер принимает ВСЁ.
// Любой логин + любой пароль = успешная авторизация.
// Фронт показывает подсказки для разных валидаций.
//
const PHANTOM_ACCOUNTS = {
    // Минимальный (не пройдёт нигде, но мы примем)
    minimal: { login: '1', password: '1', note: 'Phantom accepts literally anything' },
    // Email-формат (пройдёт email validation)
    email: { login: 'a@1.cc', password: 'Aa1!aaaa', note: 'Valid email + strong password' },
    // Длинный email (корпоративный стиль)
    corporate: { login: 'phantom@phantom-artifact.duckdns.org', password: 'Phantom1!', note: 'Corporate-style email + complex pass' },
    // Username-формат (min 3 chars)
    username: { login: 'ph1', password: 'Ph1!pass', note: 'Short username + 8-char complex password' },
    // Максимально совместимый (проходит 90%+ валидаций)
    universal: { login: 'phantom@1.cc', password: 'Phantom1!', note: 'RECOMMENDED — passes 90%+ validators' },
};

// Auth endpoints
app.post('/auth/login', (req, res) => {
    const { login, email, username, password, pass } = req.body || {};
    const user = login || email || username || 'anonymous';
    const pwd = password || pass || '';

    // Phantom принимает ВСЁ
    const token = 'phantom_session_' + crypto.randomBytes(16).toString('hex');
    res.json({
        success: true,
        token,
        token_type: 'bearer',
        expires_in: 86400,
        user: {
            id: 'phantom_' + crypto.createHash('md5').update(user).digest('hex').substring(0, 8),
            login: user,
            name: 'Phantom User',
            email: user.includes('@') ? user : user + '@phantom-artifact.duckdns.org',
            role: 'phantom',
            avatar: 'https://phantom-artifact.onrender.com/avatar.svg'
        },
        phantom: true,
        message: 'Welcome. Everyone is welcome.'
    });
});

app.post('/auth/register', (req, res) => {
    const { login, email, username, password, pass, name } = req.body || {};
    const user = login || email || username || 'anonymous';
    
    // Регистрация всегда успешна
    res.status(201).json({
        success: true,
        user: {
            id: 'phantom_' + crypto.createHash('md5').update(user).digest('hex').substring(0, 8),
            login: user,
            name: name || 'Phantom User',
            email: user.includes('@') ? user : user + '@phantom-artifact.duckdns.org',
            created_at: new Date().toISOString()
        },
        phantom: true,
        message: 'Account created. Or not. It does not matter here.'
    });
});

app.get('/auth/me', (req, res) => {
    const auth = req.headers.authorization || '';
    // Любой токен = валидная сессия
    res.json({
        authenticated: true,
        user: {
            id: 'phantom_universal',
            login: 'phantom',
            name: 'Phantom User',
            email: 'phantom@1.cc',
            role: 'phantom'
        },
        phantom: true
    });
});

app.post('/auth/logout', (req, res) => {
    res.json({ success: true, phantom: true, message: 'You never really leave.' });
});

// Справочник креденшалов
app.get('/auth/credentials', (req, res) => {
    res.json({
        note: 'Phantom accepts ANY login + ANY password. But if the frontend validates, use these:',
        recommended: PHANTOM_ACCOUNTS.universal,
        all: PHANTOM_ACCOUNTS,
        tip: 'Server always responds with success. The validation battle is on the frontend only.'
    });
});

// Avatar SVG
app.get('/avatar.svg', (req, res) => {
    res.type('image/svg+xml').send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="48" fill="#1a1a2e" stroke="#00ff41" stroke-width="2"/>
  <text x="50" y="62" text-anchor="middle" font-size="48" fill="#00ff41" font-family="monospace">\u{1F47B}</text>
</svg>`);
});

// Login страница
app.get('/login', (req, res) => {
    res.type('text/html').send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Login</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff41; 
       display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.container { background: #111; border: 1px solid #00ff41; border-radius: 8px; padding: 40px; 
             width: 380px; box-shadow: 0 0 30px rgba(0,255,65,0.1); }
h1 { text-align: center; margin-bottom: 8px; font-size: 1.4em; }
.sub { text-align: center; color: #666; font-size: 0.75em; margin-bottom: 24px; }
.field { margin-bottom: 16px; }
label { display: block; margin-bottom: 4px; font-size: 0.85em; color: #0a0; }
input { width: 100%; padding: 10px 12px; background: #0a0a0a; border: 1px solid #333; 
        color: #00ff41; font-family: inherit; font-size: 14px; border-radius: 4px; outline: none; }
input:focus { border-color: #00ff41; box-shadow: 0 0 8px rgba(0,255,65,0.2); }
input.invalid { border-color: #ff4141; }
.hint { font-size: 0.7em; color: #555; margin-top: 4px; min-height: 16px; }
.hint.err { color: #ff4141; }
btn, button { width: 100%; padding: 12px; background: #00ff41; color: #0a0a0a; border: none; 
       font-family: inherit; font-size: 14px; font-weight: bold; border-radius: 4px; 
       cursor: pointer; margin-top: 8px; }
button:hover { background: #00cc33; }
.result { margin-top: 16px; padding: 12px; background: #0a0a0a; border: 1px solid #333; 
          border-radius: 4px; font-size: 0.8em; white-space: pre-wrap; word-break: break-all; 
          max-height: 200px; overflow-y: auto; display: none; }
.presets { margin-top: 20px; border-top: 1px solid #222; padding-top: 16px; }
.presets h3 { font-size: 0.85em; color: #666; margin-bottom: 8px; }
.preset { display: inline-block; padding: 4px 10px; background: #1a1a1a; border: 1px solid #333; 
          border-radius: 12px; font-size: 0.75em; margin: 2px; cursor: pointer; color: #0a0; }
.preset:hover { border-color: #00ff41; background: #0a2a0a; }
.preset.rec { border-color: #00ff41; color: #00ff41; }
.tag { display: inline-block; padding: 2px 6px; background: #0a2a0a; border-radius: 3px; 
       font-size: 0.65em; color: #00ff41; margin-left: 4px; }
</style>
</head><body>
<div class="container">
  <h1>\u{1F47B} Phantom Login</h1>
  <div class="sub">Everyone is welcome. Any credentials work.<br>Pick a preset that passes your target's validation.</div>
  
  <div class="field">
    <label>Login / Email</label>
    <input type="text" id="login" placeholder="phantom@1.cc" autocomplete="username">
    <div class="hint" id="loginHint"></div>
  </div>
  
  <div class="field">
    <label>Password</label>
    <input type="password" id="password" placeholder="Phantom1!" autocomplete="current-password">
    <div class="hint" id="passHint"></div>
  </div>
  
  <button onclick="doLogin()">Sign In</button>
  <button onclick="doRegister()" style="background:transparent;color:#00ff41;border:1px solid #333;margin-top:8px;">Register</button>
  
  <div class="result" id="result"></div>
  
  <div class="presets">
    <h3>Presets (click to fill):</h3>
    <span class="preset rec" onclick="fill('phantom@1.cc','Phantom1!')" title="Passes 90%+ validators">
      phantom@1.cc / Phantom1! <span class="tag">recommended</span>
    </span>
    <span class="preset" onclick="fill('a@1.cc','Aa1!aaaa')" title="Shortest valid email + strong pass">
      a@1.cc / Aa1!aaaa
    </span>
    <span class="preset" onclick="fill('ph1','Ph1!pass')" title="Username format, 3+ chars">
      ph1 / Ph1!pass
    </span>
    <span class="preset" onclick="fill('1','1')" title="Minimal — server accepts, frontend may not">
      1 / 1 <span class="tag">yolo</span>
    </span>
  </div>
</div>

<script>
const API = window.location.origin;

function fill(l, p) {
  document.getElementById('login').value = l;
  document.getElementById('password').value = p;
  validate();
}

function validate() {
  const l = document.getElementById('login').value;
  const p = document.getElementById('password').value;
  const lh = document.getElementById('loginHint');
  const ph = document.getElementById('passHint');
  const li = document.getElementById('login');
  const pi = document.getElementById('password');
  
  // Login validation hints
  let lChecks = [];
  if (l.length < 3) lChecks.push('\u26a0 <3 chars (some sites need 3+)');
  if (!l.includes('@')) lChecks.push('\u26a0 no @ (email validators will reject)');
  if (l.includes('@') && !/^[^@]+@[^@]+\\.[^@]+$/.test(l)) lChecks.push('\u274c invalid email format');
  lh.innerHTML = lChecks.length ? lChecks.join(' \u00b7 ') : '\u2705 passes most validators';
  lh.className = 'hint' + (lChecks.some(c => c.includes('\u274c')) ? ' err' : '');
  li.className = lChecks.some(c => c.includes('\u274c')) ? 'invalid' : '';
  
  // Password validation hints  
  let pChecks = [];
  if (p.length < 6) pChecks.push('\u26a0 <6 chars');
  if (p.length < 8) pChecks.push('\u26a0 <8 chars (strict sites)');
  if (!/[A-Z]/.test(p)) pChecks.push('\u26a0 no uppercase');
  if (!/[a-z]/.test(p)) pChecks.push('\u26a0 no lowercase');
  if (!/[0-9]/.test(p)) pChecks.push('\u26a0 no digit');
  if (!/[!@#$%^&*]/.test(p)) pChecks.push('\u26a0 no special char');
  ph.innerHTML = pChecks.length ? pChecks.join(' \u00b7 ') : '\u2705 passes strict validators';
  ph.className = 'hint';
  pi.className = '';
}

document.getElementById('login').addEventListener('input', validate);
document.getElementById('password').addEventListener('input', validate);

async function doLogin() {
  const body = { login: document.getElementById('login').value || '1', password: document.getElementById('password').value || '1' };
  const r = await fetch(API + '/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
  const d = await r.json();
  const el = document.getElementById('result');
  el.style.display = 'block';
  el.textContent = JSON.stringify(d, null, 2);
}

async function doRegister() {
  const body = { login: document.getElementById('login').value || '1', password: document.getElementById('password').value || '1' };
  const r = await fetch(API + '/auth/register', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
  const d = await r.json();
  const el = document.getElementById('result');
  el.style.display = 'block';
  el.textContent = JSON.stringify(d, null, 2);
}

validate();
</script>
</body></html>`);
});

// ─── CORS — разрешаем всё (phantom принимает всех) ───
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    res.header('Access-Control-Allow-Headers', '*');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// ─── .well-known — валидация доменов ───
app.get('/.well-known/openid-configuration', (req, res) => {
    const host = PHANTOM_DOMAIN !== 'localhost' ? PHANTOM_DOMAIN : req.hostname;
    res.json({
        issuer: `https://${host}`,
        authorization_endpoint: `https://${host}/oauth/authorize`,
        token_endpoint: `https://${host}/oauth/token`,
        jwks_uri: `https://${host}/.well-known/jwks.json`,
        response_types_supported: ['code', 'token'],
        grant_types_supported: ['authorization_code', 'client_credentials']
    });
});

app.get('/.well-known/assetlinks.json', (req, res) => {
    res.json([{
        relation: ['delegate_permission/common.handle_all_urls'],
        target: { namespace: 'web', site: `https://${req.hostname}` }
    }]);
});

app.get('/.well-known/*', (req, res) => {
    res.json({ status: 'verified', phantom: true, path: req.path });
});

// ─── OAuth mock ───
app.get('/oauth/authorize', (req, res) => {
    const { redirect_uri, state, client_id } = req.query;
    if (redirect_uri) {
        const url = new URL(redirect_uri);
        url.searchParams.set('code', 'phantom_code_' + Date.now());
        if (state) url.searchParams.set('state', state);
        return res.redirect(302, url.toString());
    }
    res.json({
        code: 'phantom_code_' + Date.now(),
        state: req.query.state,
        phantom: true
    });
});

app.post('/oauth/token', (req, res) => {
    res.json({
        access_token: 'phantom_at_' + crypto.randomBytes(16).toString('hex'),
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'phantom_rt_' + crypto.randomBytes(16).toString('hex'),
        scope: req.body?.scope || 'read write',
        phantom: true
    });
});

// ─── Notion Integration Webhook (verification + events) ───
app.post('/webhook/notion', (req, res) => {
    const body = req.body;
    
    // Notion шлёт verification_token при создании подписки
    if (body && body.verification_token) {
        console.log('[NOTION] Verification token received:', body.verification_token);
        // Сохраняем токен для последующей валидации
        const tokenLog = {
            type: 'notion_verification',
            token: body.verification_token,
            timestamp: new Date().toISOString()
        };
        fs.appendFileSync(LOG_FILE.replace('.log', '.notion.log'), JSON.stringify(tokenLog) + '\n');
        return res.status(200).json({ status: 'ok', verification_received: true });
    }
    
    // Обычные события Notion
    console.log('[NOTION] Event:', JSON.stringify(body).substring(0, 200));
    res.status(200).json({ received: true, phantom: true });
});

// ─── Notion Database Automation Webhook (простой POST без верификации) ───
app.post('/webhook/notion-auto', (req, res) => {
    console.log('[NOTION-AUTO] Automation event:', JSON.stringify(req.body).substring(0, 500));
    res.status(200).json({ received: true, source: 'notion-automation', phantom: true });
});

// ─── Generic Webhook receiver ───
app.all('/webhook/*', (req, res) => {
    res.json({
        received: true,
        event_id: 'evt_phantom_' + Date.now(),
        path: req.path,
        phantom: true
    });
});

// ─── Payment gateway mock ───
app.post('/api/payment/charge', (req, res) => {
    res.json({
        status: 'ok',
        transaction_id: 'tx_' + crypto.randomBytes(8).toString('hex'),
        amount: req.body?.amount || 0,
        currency: req.body?.currency || 'UAH',
        charged: false,
        phantom: true,
        message: 'Phantom mode — no real charge'
    });
});

app.post('/api/payment/refund', (req, res) => {
    res.json({
        status: 'ok',
        refund_id: 'rf_' + crypto.randomBytes(8).toString('hex'),
        refunded: false,
        phantom: true
    });
});

// ─── Health / Identity ───
app.get('/health', (req, res) => {
    res.json({ status: 'alive', phantom: true, uptime: process.uptime() });
});

app.get('/identity', (req, res) => {
    const host = PHANTOM_DOMAIN !== 'localhost' ? PHANTOM_DOMAIN : req.hostname;
    res.json({
        name: 'phantom-artifact-v1',
        type: 'universal-catch-all',
        description: 'Accepts everything, owns nothing, logs everything, validates everywhere',
        layers: {
            eth: 'PhantomSink contract (deploy via CREATE2)',
            dns: host,
            api: `https://${host}`
        },
        endpoints: [
            '/identity', '/health', '/logs',
            '/webhook/*', '/oauth/authorize', '/oauth/token',
            '/api/payment/charge', '/api/payment/refund',
            '/.well-known/*', '/* (catch-all)'
        ]
    });
});

// ─── Логи (для просмотра) ───
app.get('/logs', (req, res) => {
    try {
        const logs = fs.readFileSync(LOG_FILE, 'utf-8')
            .trim()
            .split('\n')
            .slice(-50) // последние 50 записей
            .map(l => JSON.parse(l));
        res.json({ count: logs.length, entries: logs });
    } catch {
        res.json({ count: 0, entries: [] });
    }
});

// ─── HTML landing ───
app.get('/', (req, res) => {
    if (req.headers.accept?.includes('text/html')) {
        return res.send(`<!DOCTYPE html>
<html><head><title>Phantom Artifact</title>
<style>
body { font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 40px; }
h1 { color: #00ff41; } a { color: #00aaff; } code { background: #1a1a1a; padding: 2px 6px; }
pre { background: #111; padding: 16px; overflow-x: auto; border: 1px solid #333; }
</style></head><body>
<h1>👻 Phantom Artifact v1</h1>
<p>Universal catch-all identity. Accepts everything. Owns nothing. Logs everything.</p>
<h2>Endpoints</h2>
<pre>
GET  /identity          — who am I
GET  /health            — status
GET  /logs              — last 50 logged requests
POST /webhook/*         — webhook receiver
GET  /oauth/authorize   — OAuth authorize
POST /oauth/token       — OAuth token exchange
POST /api/payment/charge — payment mock
POST /api/payment/refund — refund mock
GET  /.well-known/*     — domain verification
ALL  /*                 — catch-all (logs + 200 OK)
</pre>
<h2>ETH Layer</h2>
<p>Deploy <code>PhantomSink.sol</code> via CREATE2 for deterministic on-chain identity.</p>
<h2>Philosophy</h2>
<p><code>/dev/null</code> meets <code>0x0000...dead</code> meets <code>example.com</code></p>
</body></html>`);
    }
    res.json({ phantom: true, identity: 'phantom-artifact-v1' });
});

// ─── Catch-all — принимает АБСОЛЮТНО ВСЁ ───
app.all('*', (req, res) => {
    res.json({
        status: 'ok',
        phantom: true,
        request_id: req.phantomId,
        echo: {
            method: req.method,
            path: req.path,
            query: req.query
        }
    });
});

app.listen(PORT, () => {
    console.log(`👻 Phantom Artifact listening on :${PORT}`);
    console.log(`   Logs → ${LOG_FILE}`);
    console.log(`   Identity → http://localhost:${PORT}/identity`);
});
