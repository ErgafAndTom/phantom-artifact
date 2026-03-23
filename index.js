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

// ─── In-memory stores ───
const REQUEST_BUFFER = [];
const MAX_BUFFER = 200;
const sseClients = new Set();

// ─── STATS ENGINE ───
const stats = {
    total: 0,
    started: new Date().toISOString(),
    byMethod: {},          // GET: 12, POST: 45
    byType: {},            // webhook: 30, oauth: 5, api: 10
    bySource: {},          // stripe: 4, github: 8, telegram: 2
    byConfidence: {},      // high: 20, medium: 10, low: 5
    byPath: {},            // /webhook/stripe: 4, /echo/test: 12
    byHour: {},            // "2026-03-24T01": 5, "2026-03-24T02": 12
    byMinute: [],          // rolling last 60 minutes [{minute:"HH:MM", count:N}]
    byIP: {},              // ip -> count
    byUserAgent: {},       // shortened UA -> count
    byStatusCode: {},      // 200: 100, 404: 2
    topPaths: [],          // computed on read
    topIPs: [],            // computed on read
    recentPredictions: [], // last 20 predictions with details
    flowMap: [],           // source -> type -> path connections
};

// Minute-level bucketing (rolling 60 min)
const MINUTE_BUCKETS = {};

function recordStats(entry, statusCode) {
    stats.total++;

    // Method
    stats.byMethod[entry.method] = (stats.byMethod[entry.method] || 0) + 1;

    // Predict type, source, confidence
    const predicted = entry.predicted || {};
    const pType = predicted.type || 'unknown';
    const pSource = predicted.source || 'unknown';
    const pConf = predicted.confidence || 'low';

    stats.byType[pType] = (stats.byType[pType] || 0) + 1;
    stats.bySource[pSource] = (stats.bySource[pSource] || 0) + 1;
    stats.byConfidence[pConf] = (stats.byConfidence[pConf] || 0) + 1;

    // Path (normalize to first 2 segments)
    const pathKey = entry.path.split('/').slice(0, 3).join('/') || '/';
    stats.byPath[pathKey] = (stats.byPath[pathKey] || 0) + 1;

    // Hour bucket
    const hourKey = entry.timestamp.substring(0, 13); // "2026-03-24T01"
    stats.byHour[hourKey] = (stats.byHour[hourKey] || 0) + 1;

    // Minute bucket (rolling)
    const minKey = entry.timestamp.substring(11, 16); // "01:23"
    MINUTE_BUCKETS[minKey] = (MINUTE_BUCKETS[minKey] || 0) + 1;
    // Clean old minutes (keep last 60)
    const allMinutes = Object.keys(MINUTE_BUCKETS).sort();
    if (allMinutes.length > 60) {
        delete MINUTE_BUCKETS[allMinutes[0]];
    }

    // IP
    if (entry.ip) {
        stats.byIP[entry.ip] = (stats.byIP[entry.ip] || 0) + 1;
    }

    // User Agent (shorten)
    const rawUA = entry.headers?.['user-agent'] || 'unknown';
    const shortUA = shortenUA(rawUA);
    stats.byUserAgent[shortUA] = (stats.byUserAgent[shortUA] || 0) + 1;

    // Status code
    stats.byStatusCode[statusCode] = (stats.byStatusCode[statusCode] || 0) + 1;

    // Recent predictions (last 20)
    stats.recentPredictions.unshift({
        time: entry.timestamp.substring(11, 19),
        method: entry.method,
        path: entry.path,
        type: pType,
        source: pSource,
        confidence: pConf,
        ip: entry.ip
    });
    if (stats.recentPredictions.length > 20) stats.recentPredictions.pop();

    // Flow map (last 50 unique flows)
    const flowKey = `${pSource}→${pType}→${pathKey}`;
    const existingFlow = stats.flowMap.find(f => f.key === flowKey);
    if (existingFlow) {
        existingFlow.count++;
        existingFlow.last = entry.timestamp.substring(11, 19);
    } else {
        stats.flowMap.unshift({ key: flowKey, source: pSource, type: pType, path: pathKey, count: 1, last: entry.timestamp.substring(11, 19) });
        if (stats.flowMap.length > 50) stats.flowMap.pop();
    }
}

function shortenUA(ua) {
    if (ua.includes('curl')) return 'curl';
    if (ua.includes('Postman')) return 'Postman';
    if (ua.includes('Insomnia')) return 'Insomnia';
    if (ua.includes('node-fetch') || ua.includes('undici')) return 'Node.js';
    if (ua.includes('python-requests') || ua.includes('aiohttp')) return 'Python';
    if (ua.includes('Go-http-client')) return 'Go';
    if (ua.includes('axios')) return 'Axios';
    if (ua.includes('Stripe')) return 'Stripe';
    if (ua.includes('GitHub-Hookshot')) return 'GitHub';
    if (ua.includes('TelegramBot')) return 'Telegram';
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Safari') && !ua.includes('Chrome')) return 'Safari';
    if (ua.includes('bot') || ua.includes('Bot')) return 'Bot';
    if (ua.includes('UptimeRobot') || ua.includes('pingdom')) return 'Monitor';
    if (ua.length > 40) return ua.substring(0, 30) + '...';
    return ua || 'unknown';
}

function getComputedStats() {
    // Top paths
    const topPaths = Object.entries(stats.byPath)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15)
        .map(([path, count]) => ({ path, count }));

    // Top IPs
    const topIPs = Object.entries(stats.byIP)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));

    // Timeline (last hours)
    const hourEntries = Object.entries(stats.byHour)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .slice(-24)
        .map(([hour, count]) => ({ hour: hour.substring(11) + ':00', count }));

    // Minutes timeline
    const minuteEntries = Object.entries(MINUTE_BUCKETS)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([minute, count]) => ({ minute, count }));

    return {
        ...stats,
        uptime: process.uptime(),
        topPaths,
        topIPs,
        timeline: hourEntries,
        minuteTimeline: minuteEntries,
        byMinute: undefined, // don't send raw
        byIP: undefined,     // send topIPs instead
        byPath: undefined    // send topPaths instead
    };
}

// ─── Log rotation ───
function rotateLogIfNeeded() {
    try {
        const s = fs.statSync(LOG_FILE);
        if (s.size > MAX_LOG_SIZE) {
            const rotated = LOG_FILE + '.' + Date.now();
            fs.renameSync(LOG_FILE, rotated);
            const dir = path.dirname(LOG_FILE);
            const base = path.basename(LOG_FILE);
            fs.readdirSync(dir).filter(f => f.startsWith(base + '.')).sort().reverse().slice(3).forEach(f => fs.unlinkSync(path.join(dir, f)));
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

// ─── Middleware: log + predict + stats ───
const SKIP_LOG = new Set(['/', '/inspector', '/inspector/events', '/inspector/clear', '/stats', '/stats/events', '/favicon.ico']);

app.use((req, res, next) => {
    if (SKIP_LOG.has(req.path)) return next();

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
        body: req.body && Object.keys(req.body).length ? req.body : undefined,
        ip: req.ip,
        predicted: predictRequest(req)
    };

    Object.keys(entry.headers).forEach(k => entry.headers[k] === undefined && delete entry.headers[k]);

    rotateLogIfNeeded();
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');

    REQUEST_BUFFER.push(entry);
    if (REQUEST_BUFFER.length > MAX_BUFFER) REQUEST_BUFFER.shift();

    // Stats
    const origEnd = res.end;
    res.end = function(...args) {
        recordStats(entry, res.statusCode);
        // Push to SSE
        for (const client of sseClients) {
            client.write(`data: ${JSON.stringify(entry)}\n\n`);
        }
        origEnd.apply(res, args);
    };

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
    const result = { type: 'unknown', source: 'unknown', confidence: 'low', suggestion: '', handler_template: '' };

    if (p.includes('webhook') || p.includes('hook') || p.includes('callback')) {
        result.type = 'webhook'; result.confidence = 'high';
        if (req.headers['stripe-signature'] || (body && body.type && body.data && body.data.object)) {
            result.source = 'stripe';
            result.suggestion = 'Stripe webhook. Verify with stripe.webhooks.constructEvent()';
            result.handler_template = `app.post('/webhook/stripe', (req, res) => {\n  const sig = req.headers['stripe-signature'];\n  const event = stripe.webhooks.constructEvent(req.body, sig, secret);\n  switch(event.type) {\n    case '${body?.type || 'payment_intent.succeeded'}': break;\n  }\n  res.json({received: true});\n});`;
        } else if (req.headers['x-github-event'] || req.headers['x-github-delivery']) {
            result.source = 'github';
            result.suggestion = `GitHub ${req.headers['x-github-event'] || 'push'} event`;
            result.handler_template = `app.post('/webhook/github', (req, res) => {\n  const event = req.headers['x-github-event'];\n  // verify X-Hub-Signature-256\n  res.status(200).send('ok');\n});`;
        } else if (body && (body.update_id !== undefined || body.message || body.callback_query)) {
            result.source = 'telegram';
            result.suggestion = 'Telegram Bot update';
            result.handler_template = `app.post('/webhook/telegram', (req, res) => {\n  const { message } = req.body;\n  if (message?.text) { /* handle */ }\n  res.sendStatus(200);\n});`;
        } else if (body && body.invoiceId && body.status) {
            result.source = 'monobank';
            result.suggestion = 'Monobank payment callback';
            result.handler_template = `app.post('/webhook/monobank', (req, res) => {\n  const { invoiceId, status } = req.body;\n  // verify & update order\n  res.sendStatus(200);\n});`;
        } else if (body && (body.verification_token || (body.type && String(body.type).startsWith('page')))) {
            result.source = 'notion';
            result.suggestion = 'Notion webhook event';
            result.handler_template = `app.post('/webhook/notion', (req, res) => {\n  if (req.body.verification_token) return res.json({challenge: req.body.verification_token});\n  res.json({ok: true});\n});`;
        } else {
            result.source = 'generic'; result.suggestion = 'Unknown webhook — check headers/body';
            result.handler_template = `app.post('${req.path}', (req, res) => {\n  console.log(req.body);\n  res.json({received: true});\n});`;
        }
        return result;
    }

    if (p.includes('oauth') || p.includes('authorize') || p.includes('token') || req.query.code || req.query.grant_type) {
        result.type = 'oauth'; result.confidence = 'high';
        if (req.query.code || p.includes('callback')) {
            result.source = 'oauth-callback'; result.suggestion = 'OAuth code callback — exchange for token';
        } else if (method === 'POST' && (p.includes('token') || req.query.grant_type)) {
            result.source = 'oauth-token'; result.suggestion = 'Token exchange request';
        } else {
            result.source = 'oauth-authorize'; result.suggestion = 'OAuth authorization request';
        }
        return result;
    }

    if (p.includes('payment') || p.includes('charge') || p.includes('refund') || p.includes('checkout') || p.includes('invoice')) {
        result.type = 'payment'; result.confidence = 'medium'; result.source = 'payment-api';
        result.suggestion = `Payment request${body?.amount ? ': ' + body.amount + ' ' + (body.currency || '') : ''}`;
        return result;
    }

    if (p.startsWith('/api/') || ct.includes('json')) {
        result.type = 'api'; result.confidence = 'medium'; result.source = 'rest-api';
        result.suggestion = `REST ${method} — ${method === 'POST' ? 'create' : method === 'GET' ? 'read' : method === 'DELETE' ? 'delete' : 'update'}`;
        return result;
    }

    if (p.includes('health') || p.includes('ping') || p.includes('status') || p.includes('ready')) {
        result.type = 'health-check'; result.confidence = 'high'; result.source = 'monitoring';
        result.suggestion = 'Health/readiness probe';
        return result;
    }

    if (ua.includes('bot') || ua.includes('curl') || ua.includes('postman') || ua.includes('insomnia')) {
        result.type = 'tool-request'; result.confidence = 'medium';
        result.source = ua.includes('curl') ? 'curl' : ua.includes('postman') ? 'postman' : ua.includes('insomnia') ? 'insomnia' : 'bot';
        result.suggestion = `Request from ${result.source}`;
        return result;
    }

    result.suggestion = 'Unrecognized pattern';
    return result;
}

// ─── STATS API ───
app.get('/stats', (req, res) => {
    if (req.headers.accept?.includes('text/html')) {
        return res.redirect('/');
    }
    res.json(getComputedStats());
});

app.get('/stats/events', (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write('\n');

    // Send stats every 3 seconds
    const interval = setInterval(() => {
        res.write(`data: ${JSON.stringify(getComputedStats())}\n\n`);
    }, 3000);

    req.on('close', () => clearInterval(interval));
});

// ─── INSPECTOR ───
app.get('/inspector', (req, res) => {
    res.type('text/html').send(inspectorHTML());
});

app.get('/inspector/events', (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write('\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
});

app.post('/inspector/clear', (req, res) => {
    REQUEST_BUFFER.length = 0;
    res.json({ cleared: true });
});

// ─── ECHO/MIRROR ───
app.all('/echo', echoHandler);
app.all('/echo/*', echoHandler);
app.all('/mirror', echoHandler);
app.all('/mirror/*', echoHandler);

function echoHandler(req, res) {
    const echo = {
        phantom: true, mode: 'echo',
        request: { method: req.method, path: req.path, url: req.originalUrl, query: req.query, headers: { ...req.headers }, body: req.body, ip: req.ip, protocol: req.protocol, hostname: req.hostname },
        predicted: req.phantomPredicted,
        timestamp: new Date().toISOString()
    };
    delete echo.request.headers['x-forwarded-for'];
    delete echo.request.headers['x-forwarded-proto'];
    const status = parseInt(req.query._status) || 200;
    const delay = Math.min(parseInt(req.query._delay) || 0, 30000);
    if (delay > 0) setTimeout(() => res.status(status).json(echo), delay);
    else res.status(status).json(echo);
}

// ─── .well-known ───
app.get('/.well-known/openid-configuration', (req, res) => {
    const host = PHANTOM_DOMAIN !== 'localhost' ? PHANTOM_DOMAIN : req.hostname;
    res.json({ issuer: `https://${host}`, authorization_endpoint: `https://${host}/oauth/authorize`, token_endpoint: `https://${host}/oauth/token`, jwks_uri: `https://${host}/.well-known/jwks.json`, response_types_supported: ['code', 'token'], grant_types_supported: ['authorization_code', 'client_credentials'] });
});
app.get('/.well-known/assetlinks.json', (req, res) => {
    res.json([{ relation: ['delegate_permission/common.handle_all_urls'], target: { namespace: 'web', site: `https://${req.hostname}` } }]);
});
app.get('/.well-known/*', (req, res) => { res.json({ status: 'verified', phantom: true, path: req.path }); });

// ─── OAuth mock ───
app.get('/oauth/authorize', (req, res) => {
    const { redirect_uri, state } = req.query;
    if (redirect_uri) {
        const url = new URL(redirect_uri);
        url.searchParams.set('code', 'phantom_code_' + Date.now());
        if (state) url.searchParams.set('state', state);
        return res.redirect(302, url.toString());
    }
    res.json({ code: 'phantom_code_' + Date.now(), state: req.query.state, phantom: true });
});
app.post('/oauth/token', (req, res) => {
    res.json({ access_token: 'phantom_at_' + crypto.randomBytes(16).toString('hex'), token_type: 'bearer', expires_in: 3600, refresh_token: 'phantom_rt_' + crypto.randomBytes(16).toString('hex'), scope: req.body?.scope || 'read write', phantom: true });
});

// ─── Webhooks ───
app.post('/webhook/notion', (req, res) => {
    if (req.body?.verification_token) return res.json({ status: 'ok', verification_received: true });
    res.json({ received: true, phantom: true });
});
app.post('/webhook/notion-auto', (req, res) => { res.json({ received: true, source: 'notion-automation', phantom: true }); });
app.all('/webhook/*', (req, res) => { res.json({ received: true, event_id: 'evt_phantom_' + Date.now(), path: req.path, phantom: true }); });

// ─── Payment mock ───
app.post('/api/payment/charge', (req, res) => { res.json({ status: 'ok', transaction_id: 'tx_' + crypto.randomBytes(8).toString('hex'), amount: req.body?.amount || 0, currency: req.body?.currency || 'UAH', charged: false, phantom: true }); });
app.post('/api/payment/refund', (req, res) => { res.json({ status: 'ok', refund_id: 'rf_' + crypto.randomBytes(8).toString('hex'), refunded: false, phantom: true }); });

// ─── Health / Identity ───
app.get('/health', (req, res) => { res.json({ status: 'alive', phantom: true, uptime: process.uptime() }); });
app.get('/identity', (req, res) => {
    const host = PHANTOM_DOMAIN !== 'localhost' ? PHANTOM_DOMAIN : req.hostname;
    res.json({ name: 'phantom-artifact-v2', type: 'dev-testing-toolbox', host, features: ['inspector', 'predict-engine', 'echo-mirror', 'stats-dashboard', 'webhook-catcher', 'oauth-mock', 'payment-mock'], endpoints: Object.keys(stats.byPath) });
});

// ─── Logs ───
app.get('/logs', (req, res) => {
    try {
        const logs = fs.readFileSync(LOG_FILE, 'utf-8').trim().split('\n').slice(-50).map(l => JSON.parse(l));
        res.json({ count: logs.length, entries: logs });
    } catch { res.json({ count: 0, entries: [] }); }
});

// ─── LANDING = TERMINAL + STATS DASHBOARD ───
app.get('/', (req, res) => {
    const host = PHANTOM_DOMAIN !== 'localhost' ? PHANTOM_DOMAIN : `localhost:${PORT}`;
    const baseUrl = PHANTOM_DOMAIN !== 'localhost' ? `https://${PHANTOM_DOMAIN}` : `http://localhost:${PORT}`;

    if (!req.headers.accept?.includes('text/html')) {
        return res.json({ phantom: true, identity: 'phantom-artifact-v2', inspector: '/inspector', stats: '/stats' });
    }

    res.type('text/html').send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Artifact</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0a;--surface:#111;--border:#1a1a1a;--border2:#222;--green:#00ff41;--green2:#0a2a0a;--dim:#444;--text:#999;--bright:#ccc;--blue:#4fc3f7;--orange:#ffb74d;--red:#ef5350;--purple:#ce93d8;--cyan:#00bcd4;--yellow:#ffd740}
body{font-family:'JetBrains Mono','Fira Code','Courier New',monospace;background:var(--bg);color:var(--text);min-height:100vh}
.terminal{max-width:1100px;margin:0 auto;padding:20px}

/* Top bar */
.top{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border2);margin-bottom:20px}
.top h1{color:var(--green);font-size:1.1em;letter-spacing:1px}
.top .meta{font-size:0.7em;color:var(--dim)}
.live-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--green);margin-right:4px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.badge{background:var(--green);color:var(--bg);padding:2px 8px;border-radius:10px;font-size:0.65em;font-weight:bold}

/* Grid */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--border2);border-radius:6px;padding:14px}
.card h3{color:var(--green);font-size:0.78em;margin-bottom:10px;text-transform:uppercase;letter-spacing:1px}
.card.wide{grid-column:1/-1}

/* Big numbers */
.big-nums{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.big-num{background:var(--surface);border:1px solid var(--border2);border-radius:6px;padding:14px 20px;flex:1;min-width:120px;text-align:center}
.big-num .val{font-size:1.8em;color:var(--green);font-weight:bold;line-height:1}
.big-num .label{font-size:0.65em;color:var(--dim);margin-top:4px;text-transform:uppercase}

/* Bar chart (CSS) */
.bar-chart{display:flex;flex-direction:column;gap:4px}
.bar-row{display:flex;align-items:center;gap:8px;font-size:0.75em}
.bar-row .bar-label{width:90px;text-align:right;color:var(--text);flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-row .bar-track{flex:1;height:18px;background:var(--bg);border-radius:2px;overflow:hidden;position:relative}
.bar-row .bar-fill{height:100%;border-radius:2px;transition:width .5s ease;min-width:2px}
.bar-row .bar-count{width:40px;text-align:right;color:var(--dim);flex-shrink:0;font-size:0.85em}

/* Timeline chart (sparkline) */
.timeline-chart{height:60px;display:flex;align-items:flex-end;gap:1px;padding:4px 0}
.timeline-bar{flex:1;background:var(--green);border-radius:1px 1px 0 0;min-width:2px;transition:height .5s ease;opacity:.7;position:relative}
.timeline-bar:hover{opacity:1}
.timeline-labels{display:flex;justify-content:space-between;font-size:0.6em;color:var(--dim);margin-top:2px}

/* Flow table */
.flow-table{width:100%;font-size:0.72em;border-collapse:collapse}
.flow-table th{text-align:left;color:var(--dim);font-weight:normal;padding:4px 8px;border-bottom:1px solid var(--border2)}
.flow-table td{padding:4px 8px;border-bottom:1px solid var(--border)}
.flow-table .flow-arrow{color:var(--dim)}
.tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:0.85em}
.t-webhook{background:#1a2a1a;color:#81c784}.t-oauth{background:#1a1a2a;color:#90caf9}
.t-payment{background:#2a2a1a;color:var(--orange)}.t-api{background:#1a1a1a;color:#aaa}
.t-health-check{background:#0a2a2a;color:var(--blue)}.t-unknown{background:#1a1a1a;color:#666}
.t-tool-request{background:#2a1a2a;color:var(--purple)}

/* Recent list */
.recent{font-size:0.72em}
.recent-row{display:flex;gap:8px;padding:3px 0;border-bottom:1px solid var(--border);align-items:center}
.recent-row .time{color:var(--dim);width:55px;flex-shrink:0}
.recent-row .method{width:40px;font-weight:bold;flex-shrink:0}
.m-GET{color:var(--blue)}.m-POST{color:#81c784}.m-PUT{color:var(--orange)}.m-DELETE{color:var(--red)}.m-PATCH{color:var(--purple)}
.recent-row .rpath{color:var(--bright);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.c-high{color:#81c784}.c-medium{color:var(--orange)}.c-low{color:var(--red)}

/* Nav links */
.nav{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.nav a{color:var(--green);text-decoration:none;border:1px solid var(--border2);padding:6px 14px;border-radius:4px;font-size:0.75em;transition:all .15s}
.nav a:hover{border-color:var(--green);background:var(--green2)}

/* Prompt line */
.prompt{margin-top:20px;padding:12px 0;border-top:1px solid var(--border2);font-size:0.75em;color:var(--dim)}
.prompt span{color:var(--green)}
.cursor{display:inline-block;width:8px;height:14px;background:var(--green);animation:blink 1s step-end infinite;vertical-align:text-bottom;margin-left:2px}
@keyframes blink{50%{opacity:0}}

/* Color palette for bars */
.clr-0{background:var(--green)}.clr-1{background:var(--blue)}.clr-2{background:var(--orange)}.clr-3{background:var(--purple)}.clr-4{background:var(--cyan)}.clr-5{background:var(--yellow)}.clr-6{background:var(--red)}.clr-7{background:#66bb6a}
</style></head><body>
<div class="terminal">

<div class="top">
  <h1>\u{1F47B} phantom-artifact <span style="color:var(--dim);font-size:0.7em">v2</span></h1>
  <div class="meta"><span class="badge"><span class="live-dot"></span>LIVE</span> &nbsp; <span id="uptime">0s</span></div>
</div>

<div class="nav">
  <a href="/inspector">\u{1F50D} Inspector</a>
  <a href="/echo/test">\u{1FA9E} Echo</a>
  <a href="/identity">\u{1F4CB} Identity</a>
  <a href="/logs">\u{1F4DC} Logs</a>
  <a href="/stats">\u{1F4CA} Stats JSON</a>
  <a href="https://github.com/ErgafAndTom/phantom-artifact" target="_blank">\u{1F4BB} GitHub</a>
</div>

<div class="big-nums">
  <div class="big-num"><div class="val" id="s-total">0</div><div class="label">Requests</div></div>
  <div class="big-num"><div class="val" id="s-types">0</div><div class="label">Types Seen</div></div>
  <div class="big-num"><div class="val" id="s-sources">0</div><div class="label">Sources</div></div>
  <div class="big-num"><div class="val" id="s-ips">0</div><div class="label">Unique IPs</div></div>
</div>

<div class="card wide">
  <h3>\u{1F4C8} Requests / Minute</h3>
  <div class="timeline-chart" id="chart-timeline"></div>
  <div class="timeline-labels" id="chart-timeline-labels"></div>
</div>

<div class="grid">
  <div class="card">
    <h3>\u{1F3AF} By Type (Predict)</h3>
    <div class="bar-chart" id="chart-type"></div>
  </div>
  <div class="card">
    <h3>\u{1F310} By Source</h3>
    <div class="bar-chart" id="chart-source"></div>
  </div>
  <div class="card">
    <h3>\u{1F6E0}\u{FE0F} By Method</h3>
    <div class="bar-chart" id="chart-method"></div>
  </div>
  <div class="card">
    <h3>\u{1F916} By Client</h3>
    <div class="bar-chart" id="chart-ua"></div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h3>\u{1F525} Top Paths</h3>
    <div class="bar-chart" id="chart-paths"></div>
  </div>
  <div class="card">
    <h3>\u{1F4E1} Recent Requests</h3>
    <div class="recent" id="recent-list"></div>
  </div>
</div>

<div class="card wide">
  <h3>\u{1F504} Flow Map (source \u2192 type \u2192 path)</h3>
  <table class="flow-table" id="flow-table">
    <thead><tr><th>Source</th><th></th><th>Type</th><th></th><th>Path</th><th>Count</th><th>Last</th></tr></thead>
    <tbody></tbody>
  </table>
</div>

<div class="prompt">
  <span>phantom@artifact</span>:<span style="color:var(--blue)">~</span>$ curl ${baseUrl}/webhook/test<span class="cursor"></span>
</div>

</div>

<script>
const COLORS = ['clr-0','clr-1','clr-2','clr-3','clr-4','clr-5','clr-6','clr-7'];
const TYPE_COLORS = {webhook:'var(--green)',oauth:'var(--blue)',payment:'var(--orange)',api:'#aaa','health-check':'var(--cyan)',unknown:'#666','tool-request':'var(--purple)'};
const METHOD_COLORS = {GET:'var(--blue)',POST:'#81c784',PUT:'var(--orange)',DELETE:'var(--red)',PATCH:'var(--purple)',OPTIONS:'#666'};

const es = new EventSource('/stats/events');
es.onmessage = (e) => {
    try { update(JSON.parse(e.data)); } catch(err) { console.error(err); }
};

function update(s) {
    // Big numbers
    document.getElementById('s-total').textContent = s.total;
    document.getElementById('s-types').textContent = Object.keys(s.byType || {}).length;
    document.getElementById('s-sources').textContent = Object.keys(s.bySource || {}).length;
    document.getElementById('s-ips').textContent = (s.topIPs || []).length;
    document.getElementById('uptime').textContent = formatUptime(s.uptime || 0);

    // Timeline
    renderTimeline(s.minuteTimeline || []);

    // Bar charts
    renderBars('chart-type', s.byType, TYPE_COLORS);
    renderBars('chart-source', s.bySource);
    renderBars('chart-method', s.byMethod, METHOD_COLORS);
    renderBars('chart-ua', s.byUserAgent);

    // Top paths
    renderBars('chart-paths', Object.fromEntries((s.topPaths||[]).map(p=>[p.path,p.count])));

    // Recent
    renderRecent(s.recentPredictions || []);

    // Flow
    renderFlow(s.flowMap || []);
}

function renderBars(id, data, colorMap) {
    const el = document.getElementById(id);
    if (!data || !Object.keys(data).length) { el.innerHTML = '<div style="color:var(--dim);font-size:0.75em;padding:8px">No data yet</div>'; return; }
    const sorted = Object.entries(data).sort((a,b) => b[1]-a[1]).slice(0,8);
    const max = sorted[0][1] || 1;
    el.innerHTML = sorted.map(([key,val],i) => {
        const pct = Math.max((val/max)*100, 2);
        const color = colorMap?.[key] || ('var(--green)');
        const clr = colorMap ? '' : COLORS[i % COLORS.length];
        return '<div class="bar-row">'
            + '<span class="bar-label" title="'+esc(key)+'">'+esc(key)+'</span>'
            + '<span class="bar-track"><span class="bar-fill '+(clr)+'" style="width:'+pct+'%;'+(colorMap?'background:'+color:'')+'">&nbsp;</span></span>'
            + '<span class="bar-count">'+val+'</span>'
            + '</div>';
    }).join('');
}

function renderTimeline(data) {
    const el = document.getElementById('chart-timeline');
    const labels = document.getElementById('chart-timeline-labels');
    if (!data.length) { el.innerHTML = '<div style="color:var(--dim);font-size:0.75em;padding:20px">Waiting for data...</div>'; labels.innerHTML = ''; return; }
    const max = Math.max(...data.map(d=>d.count), 1);
    el.innerHTML = data.map(d => {
        const h = Math.max((d.count/max)*56, 1);
        return '<div class="timeline-bar" style="height:'+h+'px" title="'+d.minute+': '+d.count+'"></div>';
    }).join('');
    if (data.length > 2) {
        labels.innerHTML = '<span>'+data[0].minute+'</span><span>'+data[Math.floor(data.length/2)].minute+'</span><span>'+data[data.length-1].minute+'</span>';
    }
}

function renderRecent(items) {
    const el = document.getElementById('recent-list');
    if (!items.length) { el.innerHTML = '<div style="color:var(--dim);padding:8px">No requests yet</div>'; return; }
    el.innerHTML = items.slice(0,12).map(r =>
        '<div class="recent-row">'
        + '<span class="time">'+r.time+'</span>'
        + '<span class="method m-'+r.method+'">'+r.method+'</span>'
        + '<span class="rpath">'+esc(r.path)+'</span>'
        + '<span class="tag t-'+r.type+'">'+r.type+'</span>'
        + '<span class="c-'+r.confidence+'" style="font-size:0.85em">'+r.confidence.charAt(0).toUpperCase()+'</span>'
        + '</div>'
    ).join('');
}

function renderFlow(flows) {
    const tbody = document.querySelector('#flow-table tbody');
    if (!flows.length) { tbody.innerHTML = '<tr><td colspan="7" style="color:var(--dim)">No flows yet</td></tr>'; return; }
    tbody.innerHTML = flows.slice(0,15).map(f =>
        '<tr>'
        + '<td>'+esc(f.source)+'</td>'
        + '<td class="flow-arrow">\u2192</td>'
        + '<td><span class="tag t-'+f.type+'">'+f.type+'</span></td>'
        + '<td class="flow-arrow">\u2192</td>'
        + '<td>'+esc(f.path)+'</td>'
        + '<td style="color:var(--green)">'+f.count+'</td>'
        + '<td style="color:var(--dim)">'+f.last+'</td>'
        + '</tr>'
    ).join('');
}

function formatUptime(sec) {
    if (sec < 60) return Math.floor(sec) + 's';
    if (sec < 3600) return Math.floor(sec/60) + 'm';
    if (sec < 86400) return Math.floor(sec/3600) + 'h ' + Math.floor((sec%3600)/60) + 'm';
    return Math.floor(sec/86400) + 'd ' + Math.floor((sec%86400)/3600) + 'h';
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
</script>
</body></html>`);
});

// ─── Catch-all ───
app.all('*', (req, res) => {
    res.json({ status: 'ok', phantom: true, request_id: req.phantomId, predicted: req.phantomPredicted, echo: { method: req.method, path: req.path, query: req.query } });
});

app.listen(PORT, () => {
    console.log(`\u{1F47B} Phantom Artifact v2 listening on :${PORT}`);
    console.log(`   Dashboard \u2192 http://localhost:${PORT}/`);
    console.log(`   Inspector \u2192 http://localhost:${PORT}/inspector`);
    console.log(`   Stats API \u2192 http://localhost:${PORT}/stats`);
});

// ─── Inspector HTML (separate function to keep main flow clean) ───
function inspectorHTML() {
    return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Inspector</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono','Fira Code','Courier New',monospace;background:#0a0a0a;color:#c0c0c0}
.header{background:#111;border-bottom:1px solid #222;padding:12px 20px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}
.header h1{color:#00ff41;font-size:1em}
.header .controls{display:flex;gap:8px;align-items:center}
.header .controls button{background:#1a1a1a;color:#888;border:1px solid #333;padding:4px 12px;font-family:inherit;font-size:.75em;cursor:pointer;border-radius:3px}
.header .controls button:hover{color:#00ff41;border-color:#00ff41}
.badge{background:#00ff41;color:#0a0a0a;padding:2px 8px;border-radius:10px;font-size:.7em;font-weight:bold;margin-left:8px}
.badge.off{background:#ff4141}
.container{display:flex;height:calc(100vh - 45px)}
.list{width:420px;border-right:1px solid #222;overflow-y:auto;flex-shrink:0}
.detail{flex:1;overflow-y:auto;padding:16px}
.entry{padding:10px 14px;border-bottom:1px solid #1a1a1a;cursor:pointer;transition:background .1s}
.entry:hover{background:#151515}
.entry.active{background:#0a2a0a;border-left:3px solid #00ff41}
.entry .method{display:inline-block;width:52px;font-weight:bold;font-size:.75em}
.entry .path{color:#ddd;font-size:.8em}
.entry .meta{color:#555;font-size:.65em;margin-top:3px}
.entry .predict-tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.6em;margin-left:4px}
.m-GET{color:#4fc3f7}.m-POST{color:#81c784}.m-PUT{color:#ffb74d}.m-PATCH{color:#ce93d8}.m-DELETE{color:#ef5350}
.t-webhook{background:#1a2a1a;color:#81c784}.t-oauth{background:#1a1a2a;color:#90caf9}.t-payment{background:#2a2a1a;color:#ffb74d}.t-api{background:#1a1a1a;color:#aaa}.t-health-check{background:#0a2a2a;color:#4fc3f7}.t-unknown{background:#1a1a1a;color:#666}.t-tool-request{background:#2a1a2a;color:#ce93d8}
.section{margin-bottom:20px}
.section h3{color:#00ff41;font-size:.85em;margin-bottom:8px;border-bottom:1px solid #222;padding-bottom:4px}
pre{background:#111;padding:12px;border:1px solid #222;border-radius:4px;font-size:.78em;overflow-x:auto;white-space:pre-wrap;word-break:break-all;line-height:1.5}
.predict-box{background:#0a1a0a;border:1px solid #1a3a1a;border-radius:4px;padding:12px;margin-bottom:16px}
.predict-box .type{color:#00ff41;font-weight:bold;font-size:.9em}
.predict-box .source{color:#4fc3f7;font-size:.8em}
.predict-box .suggestion{color:#ccc;font-size:.8em;margin-top:6px}
.predict-box .confidence{display:inline-block;padding:2px 6px;border-radius:3px;font-size:.65em;font-weight:bold}
.c-high{background:#1a3a1a;color:#81c784}.c-medium{background:#2a2a1a;color:#ffb74d}.c-low{background:#2a1a1a;color:#ef5350}
.code-template{position:relative}
.code-template .copy-btn{position:absolute;top:4px;right:4px;background:#222;color:#888;border:1px solid #333;padding:2px 8px;font-size:.7em;cursor:pointer;border-radius:3px;font-family:inherit}
.code-template .copy-btn:hover{color:#00ff41;border-color:#00ff41}
.empty{text-align:center;color:#444;padding:60px 20px}
.empty h2{color:#333;margin-bottom:8px;font-size:1em}
.empty code{background:#111;padding:2px 6px;color:#888}
.live-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:#00ff41;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.filter-bar{padding:8px 14px;border-bottom:1px solid #222;background:#0d0d0d}
.filter-bar input{width:100%;background:#111;border:1px solid #222;color:#ccc;padding:5px 10px;font-family:inherit;font-size:.75em;border-radius:3px;outline:none}
.filter-bar input:focus{border-color:#00ff41}
.back-link{color:#00ff41;text-decoration:none;font-size:.8em;margin-left:12px}
</style></head><body>
<div class="header">
  <h1>\u{1F47B} Inspector <a class="back-link" href="/">\u2190 Dashboard</a> <span class="badge" id="statusBadge"><span class="live-dot"></span>LIVE</span></h1>
  <div class="controls">
    <span id="counter" style="color:#555;font-size:.75em">0</span>
    <button onclick="togglePause()" id="pauseBtn">Pause</button>
    <button onclick="clearAll()">Clear</button>
  </div>
</div>
<div class="container">
  <div class="list">
    <div class="filter-bar"><input id="filter" placeholder="Filter..." oninput="applyFilter()"></div>
    <div id="entries"></div>
  </div>
  <div class="detail" id="detail"><div class="empty"><h2>No request selected</h2><p>Send a request and click it here.</p></div></div>
</div>
<script>
const entries=[];let paused=false,selected=null,filterText='';
const es=new EventSource('/inspector/events');
es.onmessage=(e)=>{if(paused)return;const entry=JSON.parse(e.data);entries.unshift(entry);if(entries.length>200)entries.pop();render()};
es.onerror=()=>{document.getElementById('statusBadge').className='badge off';document.getElementById('statusBadge').innerHTML='DISCONNECTED'};
function togglePause(){paused=!paused;document.getElementById('pauseBtn').textContent=paused?'Resume':'Pause';const b=document.getElementById('statusBadge');if(paused){b.className='badge off';b.innerHTML='PAUSED'}else{b.className='badge';b.innerHTML='<span class="live-dot"></span>LIVE'}}
function clearAll(){entries.length=0;selected=null;render();document.getElementById('detail').innerHTML='<div class="empty"><h2>Cleared</h2></div>';fetch('/inspector/clear',{method:'POST'})}
function applyFilter(){filterText=document.getElementById('filter').value.toLowerCase();render()}
function render(){
  const f=entries.filter(e=>!filterText||(e.method+' '+e.path+' '+(e.predicted?.type||'')+' '+(e.predicted?.source||'')).toLowerCase().includes(filterText));
  document.getElementById('counter').textContent=entries.length+' req';
  document.getElementById('entries').innerHTML=f.map(e=>{
    const pt=e.predicted?.type||'unknown';
    return '<div class="entry'+(selected===e.id?' active':'')+'" onclick="showDetail(\\''+e.id+'\\')">'
      +'<span class="method m-'+e.method+'">'+e.method+'</span> <span class="path">'+esc(e.path)+'</span>'
      +'<span class="predict-tag t-'+pt+'">'+pt+'</span>'
      +'<div class="meta">'+e.timestamp.substring(11,19)+' \xb7 '+(e.ip||'')+'</div></div>';
  }).join('');
}
function showDetail(id){
  selected=id;const e=entries.find(x=>x.id===id);if(!e)return;render();
  const pr=e.predicted||{};let h='';
  h+='<div class="predict-box"><div><span class="type">'+(pr.type||'?')+'</span> <span class="confidence c-'+(pr.confidence||'low')+'">'+(pr.confidence||'?')+'</span></div><div class="source">'+(pr.source||'')+'</div><div class="suggestion">'+esc(pr.suggestion||'')+'</div></div>';
  if(pr.handler_template)h+='<div class="section"><h3>Handler</h3><div class="code-template"><button class="copy-btn" onclick="navigator.clipboard.writeText(this.nextElementSibling.textContent).then(()=>{this.textContent=\\'Copied!\\';setTimeout(()=>this.textContent=\\'Copy\\',1500)})">Copy</button><pre>'+esc(pr.handler_template)+'</pre></div></div>';
  h+='<div class="section"><h3>Request</h3><pre>'+esc(e.method+' '+e.path)+'</pre></div>';
  if(e.headers&&Object.keys(e.headers).length)h+='<div class="section"><h3>Headers</h3><pre>'+esc(JSON.stringify(e.headers,null,2))+'</pre></div>';
  if(e.body)h+='<div class="section"><h3>Body</h3><pre>'+esc(typeof e.body==='object'?JSON.stringify(e.body,null,2):String(e.body))+'</pre></div>';
  h+='<div class="section"><h3>Raw</h3><pre>'+esc(JSON.stringify(e,null,2))+'</pre></div>';
  document.getElementById('detail').innerHTML=h;
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
</script></body></html>`;
}
