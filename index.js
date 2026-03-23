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
