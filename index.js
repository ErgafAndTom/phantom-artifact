const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.set('trust proxy', true);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.raw({ type: '*/*', limit: '10mb' }));

const LOG_DIR = process.env.LOG_DIR || '.';
const LOG_FILE = path.join(LOG_DIR, 'phantom.log');
const MAX_LOG_SIZE = 5 * 1024 * 1024;
const PORT = process.env.PORT || 3000;
const PHANTOM_DOMAIN = process.env.PHANTOM_DOMAIN || 'localhost';

// In-memory ring buffer for inspector UI (last 200 requests)
const REQUEST_BUFFER = [];
const MAX_BUFFER = 200;

// SSE clients for live inspector
const sseClients = new Set();

// ─── Log rotation ───
function rotateLogIfNeeded() {
    try {
        const stats = fs.statSync(LOG_FILE);
        if (stats.size > MAX_LOG_SIZE) {
            const rotated = LOG_FILE + '.' + Date.now();
            fs.renameSync(LOG_FILE, rotated);
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

// ─── CORS ───
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    res.header('Access-Control-Allow-Headers', '*');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// ─── Middleware: log everything + push to inspector ───
app.use((req, res, next) => {
    // Skip inspector/SSE routes from logging
    if (req.path === '/inspector' || req.path === '/inspector/events' || req.path === '/inspector/clear') {
        return next();
    }

    const entry = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        query: Object.keys(req.query).length ? req.query : undefined,
        headers: {
            'user-agent': req.headers['user-agent'],
            'content-type': req.headers['content-type'],
            'authorization': req.headers['authorization'] ? '[PRESENT]' : undefined,
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'origin': req.headers['origin'],
            'referer': req.headers['referer'],
            'accept': req.headers['accept']
        },
        body: req.body && Object.keys(req.body).length ? req.body : (typeof req.body === 'string' && req.body.length ? req.body : undefined),
        ip: req.ip,
        predicted: predictRequest(req)
    };

    // Clean undefined values from headers
    Object.keys(entry.headers).forEach(k => entry.headers[k] === undefined && delete entry.headers[k]);

    // File log
    rotateLogIfNeeded();
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');

    // Ring buffer for inspector
    REQUEST_BUFFER.push(entry);
    if (REQUEST_BUFFER.length > MAX_BUFFER) REQUEST_BUFFER.shift();

    // Push to SSE clients
    for (const client of sseClients) {
        client.write(`data: ${JSON.stringify(entry)}\n\n`);
    }

    req.phantomId = entry.id;
    req.phantomPredicted = entry.predicted;
    next();
});

// ─── PREDICT ENGINE ───
function predictRequest(req) {
    const p = req.path.toLowerCase();
    const ct = (req.headers['content-type'] || '').toLowerCase();
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const body = req.body;
    const method = req.method;

    const result = {
        type: 'unknown',
        source: 'unknown',
        confidence: 'low',
        suggestion: '',
        handler_template: ''
    };

    // --- Webhook detection ---
    if (p.includes('webhook') || p.includes('hook') || p.includes('callback')) {
        result.type = 'webhook';
        result.confidence = 'high';

        // Stripe
        if (req.headers['stripe-signature'] || (body && body.type && body.data && body.data.object)) {
            result.source = 'stripe';
            result.suggestion = 'Stripe webhook event. Verify signature with stripe.webhooks.constructEvent()';
            result.handler_template = `app.post('/webhook/stripe', (req, res) => {\n  const sig = req.headers['stripe-signature'];\n  const event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);\n  switch(event.type) {\n    case '${body?.type || 'payment_intent.succeeded'}':\n      // handle\n      break;\n  }\n  res.json({received: true});\n});`;
            return result;
        }

        // GitHub
        if (req.headers['x-github-event'] || req.headers['x-github-delivery']) {
            result.source = 'github';
            const event = req.headers['x-github-event'] || 'push';
            result.suggestion = `GitHub ${event} event. Verify with X-Hub-Signature-256.`;
            result.handler_template = `app.post('/webhook/github', (req, res) => {\n  const event = req.headers['x-github-event'];\n  const payload = req.body;\n  // Verify: crypto.timingSafeEqual(hmac, signature)\n  switch(event) {\n    case '${event}': /* handle */ break;\n  }\n  res.status(200).send('ok');\n});`;
            return result;
        }

        // Telegram
        if (body && (body.update_id !== undefined || body.message || body.callback_query)) {
            result.source = 'telegram';
            result.suggestion = 'Telegram Bot webhook update. Set via bot.setWebhook(url).';
            result.handler_template = `app.post('/webhook/telegram', (req, res) => {\n  const { message, callback_query } = req.body;\n  if (message?.text) {\n    // handle text: message.text, chat: message.chat.id\n  }\n  res.sendStatus(200);\n});`;
            return result;
        }

        // Monobank
        if (body && body.invoiceId && body.status) {
            result.source = 'monobank';
            result.suggestion = 'Monobank payment callback. Verify invoiceId against your records.';
            result.handler_template = `app.post('/webhook/monobank', (req, res) => {\n  const { invoiceId, status, amount } = req.body;\n  if (status === 'success') {\n    // update order by invoiceId\n  }\n  res.sendStatus(200);\n});`;
            return result;
        }

        // Notion
        if (body && (body.verification_token || (body.type && body.type.startsWith('page')))) {
            result.source = 'notion';
            result.suggestion = 'Notion webhook/automation event.';
            result.handler_template = `app.post('/webhook/notion', (req, res) => {\n  if (req.body.verification_token) {\n    return res.json({ challenge: req.body.verification_token });\n  }\n  // handle event\n  res.json({ ok: true });\n});`;
            return result;
        }

        // Generic webhook
        result.source = 'generic';
        result.suggestion = 'Unknown webhook. Log body and headers to identify the service.';
        result.handler_template = `app.post('${req.path}', (req, res) => {\n  console.log('webhook:', JSON.stringify(req.body));\n  res.json({ received: true });\n});`;
        return result;
    }

    // --- OAuth detection ---
    if (p.includes('oauth') || p.includes('authorize') || p.includes('token') || req.query.code || req.query.grant_type) {
        result.type = 'oauth';
        result.confidence = 'high';

        if (req.query.code || p.includes('callback')) {
            result.source = 'oauth-callback';
            result.suggestion = 'OAuth authorization code callback. Exchange code for token.';
            result.handler_template = `app.get('/oauth/callback', async (req, res) => {\n  const { code, state } = req.query;\n  const token = await exchangeCodeForToken(code);\n  // store token, redirect user\n  res.redirect('/dashboard');\n});`;
        } else if (method === 'POST' && (p.includes('token') || req.query.grant_type)) {
            result.source = 'oauth-token-exchange';
            result.suggestion = 'Token exchange request. Return access_token + refresh_token.';
            result.handler_template = `app.post('/oauth/token', (req, res) => {\n  const { grant_type, code, refresh_token } = req.body;\n  // validate & issue tokens\n  res.json({\n    access_token: '...',\n    token_type: 'bearer',\n    expires_in: 3600\n  });\n});`;
        } else {
            result.source = 'oauth-authorize';
            result.suggestion = 'OAuth authorization request. Show consent screen or redirect with code.';
        }
        return result;
    }

    // --- Payment detection ---
    if (p.includes('payment') || p.includes('charge') || p.includes('refund') || p.includes('checkout') || p.includes('invoice')) {
        result.type = 'payment';
        result.confidence = 'medium';
        result.source = body?.currency ? 'payment-api' : 'payment-generic';
        result.suggestion = `Payment-related request. ${body?.amount ? `Amount: ${body.amount} ${body.currency || ''}` : 'Parse amount from body.'}`;
        result.handler_template = `app.post('${req.path}', (req, res) => {\n  const { amount, currency, orderId } = req.body;\n  // process payment\n  res.json({ status: 'ok', transactionId: crypto.randomUUID() });\n});`;
        return result;
    }

    // --- API/REST detection ---
    if (p.startsWith('/api/') || ct.includes('json')) {
        result.type = 'api';
        result.confidence = 'medium';

        if (method === 'GET') {
            result.suggestion = 'API GET request — likely fetching data. Return JSON array or object.';
        } else if (method === 'POST') {
            result.suggestion = 'API POST — likely creating a resource. Return 201 with created object.';
        } else if (method === 'PUT' || method === 'PATCH') {
            result.suggestion = 'API update request. Return updated resource.';
        } else if (method === 'DELETE') {
            result.suggestion = 'API delete request. Return 204 or confirmation.';
        }

        result.source = 'rest-api';
        result.handler_template = `app.${method.toLowerCase()}('${req.path}', (req, res) => {\n  // handle ${method}\n  res.status(${method === 'POST' ? 201 : method === 'DELETE' ? 204 : 200}).json({ ok: true });\n});`;
        return result;
    }

    // --- Health check detection ---
    if (p.includes('health') || p.includes('ping') || p.includes('status') || p.includes('ready')) {
        result.type = 'health-check';
        result.confidence = 'high';
        result.source = 'monitoring';
        result.suggestion = 'Health check probe (likely Kubernetes, UptimeRobot, or load balancer).';
        result.handler_template = `app.get('${req.path}', (req, res) => {\n  res.json({ status: 'ok', uptime: process.uptime() });\n});`;
        return result;
    }

    // --- Bot/Crawler detection ---
    if (ua.includes('bot') || ua.includes('crawler') || ua.includes('spider') || ua.includes('curl') || ua.includes('postman') || ua.includes('insomnia')) {
        result.type = 'tool-request';
        result.confidence = 'medium';
        if (ua.includes('curl')) result.source = 'curl';
        else if (ua.includes('postman')) result.source = 'postman';
        else if (ua.includes('insomnia')) result.source = 'insomnia';
        else result.source = 'bot/crawler';
        result.suggestion = `Request from ${result.source}. Probably manual testing.`;
        return result;
    }

    // --- Fallback ---
    result.suggestion = 'Unrecognized request pattern. Check headers and body for clues.';
    return result;
}

// ─── REQUEST INSPECTOR UI ───
app.get('/inspector', (req, res) => {
    res.type('text/html').send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Inspector</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace; background: #0a0a0a; color: #c0c0c0; }
.header { background: #111; border-bottom: 1px solid #222; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 10; }
.header h1 { color: #00ff41; font-size: 1em; }
.header .controls { display: flex; gap: 8px; align-items: center; }
.header .controls button { background: #1a1a1a; color: #888; border: 1px solid #333; padding: 4px 12px; font-family: inherit; font-size: 0.75em; cursor: pointer; border-radius: 3px; }
.header .controls button:hover { color: #00ff41; border-color: #00ff41; }
.badge { background: #00ff41; color: #0a0a0a; padding: 2px 8px; border-radius: 10px; font-size: 0.7em; font-weight: bold; margin-left: 8px; }
.badge.off { background: #ff4141; }
.container { display: flex; height: calc(100vh - 45px); }
.list { width: 420px; border-right: 1px solid #222; overflow-y: auto; flex-shrink: 0; }
.detail { flex: 1; overflow-y: auto; padding: 16px; }
.entry { padding: 10px 14px; border-bottom: 1px solid #1a1a1a; cursor: pointer; transition: background 0.1s; }
.entry:hover { background: #151515; }
.entry.active { background: #0a2a0a; border-left: 3px solid #00ff41; }
.entry .method { display: inline-block; width: 52px; font-weight: bold; font-size: 0.75em; }
.entry .path { color: #ddd; font-size: 0.8em; }
.entry .meta { color: #555; font-size: 0.65em; margin-top: 3px; }
.entry .predict-tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.6em; margin-left: 4px; }
.m-GET { color: #4fc3f7; } .m-POST { color: #81c784; } .m-PUT { color: #ffb74d; }
.m-PATCH { color: #ce93d8; } .m-DELETE { color: #ef5350; } .m-OPTIONS { color: #666; }
.t-webhook { background: #1a2a1a; color: #81c784; } .t-oauth { background: #1a1a2a; color: #90caf9; }
.t-payment { background: #2a2a1a; color: #ffb74d; } .t-api { background: #1a1a1a; color: #aaa; }
.t-health-check { background: #0a2a2a; color: #4fc3f7; } .t-unknown { background: #1a1a1a; color: #666; }
.t-tool-request { background: #2a1a2a; color: #ce93d8; }
.section { margin-bottom: 20px; }
.section h3 { color: #00ff41; font-size: 0.85em; margin-bottom: 8px; border-bottom: 1px solid #222; padding-bottom: 4px; }
pre { background: #111; padding: 12px; border: 1px solid #222; border-radius: 4px; font-size: 0.78em; overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.5; }
.predict-box { background: #0a1a0a; border: 1px solid #1a3a1a; border-radius: 4px; padding: 12px; margin-bottom: 16px; }
.predict-box .type { color: #00ff41; font-weight: bold; font-size: 0.9em; }
.predict-box .source { color: #4fc3f7; font-size: 0.8em; }
.predict-box .suggestion { color: #ccc; font-size: 0.8em; margin-top: 6px; }
.predict-box .confidence { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.65em; font-weight: bold; }
.c-high { background: #1a3a1a; color: #81c784; } .c-medium { background: #2a2a1a; color: #ffb74d; } .c-low { background: #2a1a1a; color: #ef5350; }
.code-template { position: relative; }
.code-template .copy-btn { position: absolute; top: 4px; right: 4px; background: #222; color: #888; border: 1px solid #333; padding: 2px 8px; font-size: 0.7em; cursor: pointer; border-radius: 3px; font-family: inherit; }
.code-template .copy-btn:hover { color: #00ff41; border-color: #00ff41; }
.empty { text-align: center; color: #444; padding: 60px 20px; }
.empty h2 { color: #333; margin-bottom: 8px; font-size: 1em; }
.empty code { background: #111; padding: 2px 6px; color: #888; }
.live-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #00ff41; margin-right: 6px; animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
.filter-bar { padding: 8px 14px; border-bottom: 1px solid #222; background: #0d0d0d; }
.filter-bar input { width: 100%; background: #111; border: 1px solid #222; color: #ccc; padding: 5px 10px; font-family: inherit; font-size: 0.75em; border-radius: 3px; outline: none; }
.filter-bar input:focus { border-color: #00ff41; }
</style></head><body>
<div class="header">
  <h1>\u{1F47B} Phantom Inspector <span class="badge" id="statusBadge"><span class="live-dot"></span>LIVE</span></h1>
  <div class="controls">
    <span id="counter" style="color:#555;font-size:0.75em;">0 requests</span>
    <button onclick="togglePause()" id="pauseBtn">Pause</button>
    <button onclick="clearAll()">Clear</button>
  </div>
</div>
<div class="container">
  <div class="list">
    <div class="filter-bar"><input id="filter" placeholder="Filter by path, method, type..." oninput="applyFilter()"></div>
    <div id="entries"></div>
  </div>
  <div class="detail" id="detail">
    <div class="empty">
      <h2>No request selected</h2>
      <p>Send a request to this server and click it in the list.</p>
      <p style="margin-top:12px;font-size:0.8em;color:#555;">
        Try: <code>curl ${PHANTOM_DOMAIN !== 'localhost' ? 'https://' + PHANTOM_DOMAIN : 'http://localhost:' + PORT}/test</code>
      </p>
    </div>
  </div>
</div>
<script>
const entries = [];
let paused = false;
let selected = null;
let filterText = '';

const es = new EventSource('/inspector/events');
es.onmessage = (e) => {
  if (paused) return;
  const entry = JSON.parse(e.data);
  entries.unshift(entry);
  if (entries.length > 200) entries.pop();
  render();
};
es.onerror = () => {
  document.getElementById('statusBadge').className = 'badge off';
  document.getElementById('statusBadge').innerHTML = 'DISCONNECTED';
};

function togglePause() {
  paused = !paused;
  document.getElementById('pauseBtn').textContent = paused ? 'Resume' : 'Pause';
  const b = document.getElementById('statusBadge');
  if (paused) { b.className = 'badge off'; b.innerHTML = 'PAUSED'; }
  else { b.className = 'badge'; b.innerHTML = '<span class="live-dot"></span>LIVE'; }
}

function clearAll() {
  entries.length = 0;
  selected = null;
  render();
  document.getElementById('detail').innerHTML = '<div class="empty"><h2>Cleared</h2></div>';
  fetch('/inspector/clear', { method: 'POST' });
}

function applyFilter() {
  filterText = document.getElementById('filter').value.toLowerCase();
  render();
}

function render() {
  const filtered = entries.filter(e => {
    if (!filterText) return true;
    return (e.method + ' ' + e.path + ' ' + (e.predicted?.type || '') + ' ' + (e.predicted?.source || '')).toLowerCase().includes(filterText);
  });
  document.getElementById('counter').textContent = entries.length + ' requests';
  const el = document.getElementById('entries');
  el.innerHTML = filtered.map((e, i) => {
    const pt = e.predicted?.type || 'unknown';
    return '<div class="entry' + (selected === e.id ? ' active' : '') + '" onclick="showDetail(\\'' + e.id + '\\')">'
      + '<span class="method m-' + e.method + '">' + e.method + '</span> '
      + '<span class="path">' + escH(e.path) + '</span>'
      + '<span class="predict-tag t-' + pt + '">' + pt + '</span>'
      + '<div class="meta">' + e.timestamp.substring(11, 19) + ' \u00b7 ' + (e.ip || '') + (e.predicted?.source && e.predicted.source !== 'unknown' ? ' \u00b7 ' + e.predicted.source : '') + '</div>'
      + '</div>';
  }).join('');
}

function showDetail(id) {
  selected = id;
  const e = entries.find(x => x.id === id);
  if (!e) return;
  render();

  const pr = e.predicted || {};
  let html = '';

  // Predict box
  html += '<div class="predict-box">'
    + '<div><span class="type">' + (pr.type || 'unknown') + '</span>'
    + ' <span class="confidence ' + 'c-' + (pr.confidence || 'low') + '">' + (pr.confidence || 'low') + '</span></div>'
    + '<div class="source">' + (pr.source || '') + '</div>'
    + '<div class="suggestion">' + escH(pr.suggestion || '') + '</div>'
    + '</div>';

  // Handler template
  if (pr.handler_template) {
    html += '<div class="section"><h3>\u{1F4CB} Suggested Handler</h3>'
      + '<div class="code-template"><button class="copy-btn" onclick="copyCode(this)">Copy</button>'
      + '<pre>' + escH(pr.handler_template) + '</pre></div></div>';
  }

  // Request details
  html += '<div class="section"><h3>\u{1F4E8} Request</h3><pre>'
    + escH(e.method + ' ' + e.path + (e.query && Object.keys(e.query).length ? '?' + new URLSearchParams(e.query) : ''))
    + '</pre></div>';

  // Headers
  if (e.headers && Object.keys(e.headers).length) {
    html += '<div class="section"><h3>\u{1F4E4} Headers</h3><pre>'
      + escH(JSON.stringify(e.headers, null, 2)) + '</pre></div>';
  }

  // Body
  if (e.body) {
    html += '<div class="section"><h3>\u{1F4E6} Body</h3><pre>'
      + escH(typeof e.body === 'object' ? JSON.stringify(e.body, null, 2) : String(e.body)) + '</pre></div>';
  }

  // Query
  if (e.query && Object.keys(e.query).length) {
    html += '<div class="section"><h3>\u{1F50E} Query Params</h3><pre>'
      + escH(JSON.stringify(e.query, null, 2)) + '</pre></div>';
  }

  // Raw
  html += '<div class="section"><h3>\u{1F9FE} Raw Entry</h3><pre>'
    + escH(JSON.stringify(e, null, 2)) + '</pre></div>';

  document.getElementById('detail').innerHTML = html;
}

function copyCode(btn) {
  const code = btn.nextElementSibling.textContent;
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 1500);
  });
}

function escH(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body></html>`);
});

// SSE endpoint for live inspector
app.get('/inspector/events', (req, res) => {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    res.write('\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
});

// Clear inspector buffer
app.post('/inspector/clear', (req, res) => {
    REQUEST_BUFFER.length = 0;
    res.json({ cleared: true });
});

// ─── ECHO/MIRROR MODE ───
// Returns exactly what was received — headers, body, query, method
app.all('/echo', echoHandler);
app.all('/echo/*', echoHandler);
app.all('/mirror', echoHandler);
app.all('/mirror/*', echoHandler);

function echoHandler(req, res) {
    const echo = {
        phantom: true,
        mode: 'echo',
        request: {
            method: req.method,
            path: req.path,
            url: req.originalUrl,
            query: req.query,
            headers: { ...req.headers },
            body: req.body,
            ip: req.ip,
            protocol: req.protocol,
            hostname: req.hostname
        },
        predicted: req.phantomPredicted,
        timestamp: new Date().toISOString()
    };

    // Remove sensitive proxy headers
    delete echo.request.headers['x-forwarded-for'];
    delete echo.request.headers['x-forwarded-proto'];
    delete echo.request.headers['x-forwarded-host'];

    // Support custom response via query params
    const status = parseInt(req.query._status) || 200;
    const delay = parseInt(req.query._delay) || 0;

    if (delay > 0) {
        setTimeout(() => res.status(status).json(echo), Math.min(delay, 30000));
    } else {
        res.status(status).json(echo);
    }
}

// ─── .well-known — domain verification ───
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
    const { redirect_uri, state } = req.query;
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

// ─── Webhook receivers ───
app.post('/webhook/notion', (req, res) => {
    const body = req.body;
    if (body && body.verification_token) {
        console.log('[NOTION] Verification:', body.verification_token);
        return res.status(200).json({ status: 'ok', verification_received: true });
    }
    res.status(200).json({ received: true, phantom: true });
});

app.post('/webhook/notion-auto', (req, res) => {
    console.log('[NOTION-AUTO]', JSON.stringify(req.body).substring(0, 500));
    res.status(200).json({ received: true, source: 'notion-automation', phantom: true });
});

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
        name: 'phantom-artifact-v2',
        type: 'dev-testing-toolbox',
        description: 'Catch-all server for development: receives everything, predicts request type, suggests handlers, mirrors requests',
        layers: {
            eth: 'PhantomSink contract (deploy via CREATE2)',
            dns: host,
            api: `https://${host}`
        },
        features: [
            'Request Inspector UI — live stream of all requests',
            'Predict Engine — identifies webhook source, suggests handler code',
            'Echo/Mirror Mode — returns exactly what was received',
            'Webhook receiver — any path under /webhook/*',
            'OAuth mock provider — /oauth/authorize, /oauth/token',
            'Payment mock — /api/payment/charge, /api/payment/refund',
            'Domain verification — /.well-known/*',
            'Catch-all — everything else returns 200 OK'
        ],
        endpoints: [
            'GET  /inspector       — live request inspector UI',
            'ALL  /echo/*          — echo/mirror mode',
            'ALL  /mirror/*        — echo/mirror mode (alias)',
            'GET  /identity        — this info',
            'GET  /health          — status',
            'GET  /logs            — last 50 logged requests',
            'ALL  /webhook/*       — webhook receiver',
            'GET  /oauth/authorize — OAuth authorize',
            'POST /oauth/token     — OAuth token exchange',
            'POST /api/payment/*   — payment mock',
            'GET  /.well-known/*   — domain verification',
            'ALL  /*               — catch-all (logs + 200 OK + predict)'
        ]
    });
});

// ─── Logs ───
app.get('/logs', (req, res) => {
    try {
        const logs = fs.readFileSync(LOG_FILE, 'utf-8')
            .trim()
            .split('\n')
            .slice(-50)
            .map(l => JSON.parse(l));
        res.json({ count: logs.length, entries: logs });
    } catch {
        res.json({ count: 0, entries: [] });
    }
});

// ─── HTML landing ───
app.get('/', (req, res) => {
    const host = PHANTOM_DOMAIN !== 'localhost' ? PHANTOM_DOMAIN : `localhost:${PORT}`;
    const baseUrl = PHANTOM_DOMAIN !== 'localhost' ? `https://${PHANTOM_DOMAIN}` : `http://localhost:${PORT}`;

    if (req.headers.accept?.includes('text/html')) {
        return res.send(`<!DOCTYPE html>
<html><head><title>Phantom Artifact</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace; background: #0a0a0a; color: #c0c0c0; padding: 40px; max-width: 800px; margin: 0 auto; line-height: 1.6; }
h1 { color: #00ff41; font-size: 1.5em; margin-bottom: 4px; }
h2 { color: #00ff41; font-size: 1em; margin: 24px 0 8px; border-bottom: 1px solid #222; padding-bottom: 4px; }
.sub { color: #666; font-size: 0.85em; margin-bottom: 24px; }
a { color: #4fc3f7; text-decoration: none; }
a:hover { text-decoration: underline; }
code { background: #1a1a1a; padding: 2px 6px; color: #00ff41; border-radius: 2px; font-size: 0.9em; }
pre { background: #111; padding: 16px; overflow-x: auto; border: 1px solid #222; border-radius: 4px; margin: 8px 0; font-size: 0.85em; }
.feature { display: flex; gap: 12px; margin: 8px 0; padding: 8px 0; }
.feature .icon { flex-shrink: 0; font-size: 1.2em; }
.feature .text { flex: 1; }
.feature .text strong { color: #ddd; }
.feature .text p { color: #888; font-size: 0.85em; }
.hero-btn { display: inline-block; background: #00ff41; color: #0a0a0a; padding: 10px 24px; font-weight: bold; font-family: inherit; border-radius: 4px; margin: 16px 8px 16px 0; }
.hero-btn:hover { text-decoration: none; background: #00cc33; }
.hero-btn.secondary { background: transparent; color: #00ff41; border: 1px solid #00ff41; }
.hero-btn.secondary:hover { background: #0a2a0a; }
</style></head><body>
<h1>\u{1F47B} Phantom Artifact <span style="color:#555;font-size:0.6em;">v2</span></h1>
<p class="sub">Dev Testing Toolbox \u2014 catch-all server that receives everything, predicts what it is, and suggests how to handle it.</p>

<a class="hero-btn" href="/inspector">Open Inspector</a>
<a class="hero-btn secondary" href="/identity">API Info</a>

<h2>What it does</h2>

<div class="feature">
  <div class="icon">\u{1F50D}</div>
  <div class="text">
    <strong>Request Inspector</strong>
    <p>Live web UI showing every incoming request in real-time. See headers, body, query params, and predicted request type.</p>
  </div>
</div>

<div class="feature">
  <div class="icon">\u{1F9E0}</div>
  <div class="text">
    <strong>Predict Engine</strong>
    <p>Automatically identifies the request \u2014 Stripe webhook? GitHub push? Telegram bot? OAuth callback? Shows confidence level and generates a handler template you can copy.</p>
  </div>
</div>

<div class="feature">
  <div class="icon">\u{1FA9E}</div>
  <div class="text">
    <strong>Echo/Mirror</strong>
    <p>Send anything to <code>/echo/*</code> \u2014 get back exactly what you sent. Debug your client. Add <code>?_delay=2000</code> to test timeouts, <code>?_status=500</code> for error responses.</p>
  </div>
</div>

<div class="feature">
  <div class="icon">\u{1F4E1}</div>
  <div class="text">
    <strong>Webhook Catcher</strong>
    <p>Point any webhook to <code>/webhook/anything</code> \u2014 always responds 200 OK, logs everything for inspection.</p>
  </div>
</div>

<div class="feature">
  <div class="icon">\u{1F511}</div>
  <div class="text">
    <strong>OAuth Mock</strong>
    <p>Full OAuth2 flow: <code>/oauth/authorize</code>, <code>/oauth/token</code>, <code>/.well-known/openid-configuration</code>. Test your OAuth integration without a real provider.</p>
  </div>
</div>

<div class="feature">
  <div class="icon">\u{1F4B3}</div>
  <div class="text">
    <strong>Payment Mock</strong>
    <p><code>/api/payment/charge</code> and <code>/api/payment/refund</code> \u2014 returns valid-looking responses without processing real money.</p>
  </div>
</div>

<h2>Quick Start</h2>
<pre>
# Test webhook
curl -X POST ${baseUrl}/webhook/stripe \\
  -H "Content-Type: application/json" \\
  -d '{"type":"payment_intent.succeeded","data":{"object":{"amount":2000}}}'

# Echo with delay
curl ${baseUrl}/echo/test?_delay=3000&_status=201

# Mirror your request
curl -X POST ${baseUrl}/mirror \\
  -H "Content-Type: application/json" \\
  -H "X-Custom: hello" \\
  -d '{"test": true}'

# Open inspector
open ${baseUrl}/inspector
</pre>

<h2>Philosophy</h2>
<p style="color:#555;font-size:0.85em;"><code>/dev/null</code> meets <code>RequestBin</code> meets <code>json-server</code> \u2014 one URL that handles everything during development.</p>

<p style="margin-top:24px;font-size:0.8em;color:#333;">
  ETH Layer: deploy <code>PhantomSink.sol</code> via CREATE2 for on-chain identity \u00b7
  <a href="https://github.com/ErgafAndTom/phantom-artifact">GitHub</a>
</p>
</body></html>`);
    }
    res.json({ phantom: true, identity: 'phantom-artifact-v2', inspector: '/inspector' });
});

// ─── Catch-all ───
app.all('*', (req, res) => {
    res.json({
        status: 'ok',
        phantom: true,
        request_id: req.phantomId,
        predicted: req.phantomPredicted,
        echo: {
            method: req.method,
            path: req.path,
            query: req.query
        }
    });
});

app.listen(PORT, () => {
    console.log(`\u{1F47B} Phantom Artifact v2 listening on :${PORT}`);
    console.log(`   Inspector \u2192 http://localhost:${PORT}/inspector`);
    console.log(`   Identity  \u2192 http://localhost:${PORT}/identity`);
    console.log(`   Logs      \u2192 ${LOG_FILE}`);
});
