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
const LANDING_HTML = fs.readFileSync(path.join(__dirname, 'landing.html'), 'utf-8');

app.get('/', (req, res) => {

    if (!req.headers.accept?.includes('text/html')) {
        return res.json({ phantom: true, identity: 'phantom-artifact-v2', inspector: '/inspector', stats: '/stats' });
    }

    res.type('text/html').send(LANDING_HTML);
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

// ─── Inspector HTML ───
function inspectorHTML() {
    return fs.readFileSync(path.join(__dirname, 'inspector.html'), 'utf-8');
}
