# Phantom Artifact v2 — Dev Testing Toolbox

> Catch-all server that receives everything, predicts what it is, and suggests how to handle it.

`/dev/null` meets `RequestBin` meets `json-server` — one URL that handles everything during development.

---

## What it does

### 🔍 Request Inspector
Live web UI at `/inspector` showing every incoming request in real-time via Server-Sent Events. See method, path, headers, body, query params, and predicted type — all streaming as they arrive. Pause, filter, clear.

### 🧠 Predict Engine
Automatically identifies requests:
- **Stripe webhook** → detects `stripe-signature`, body structure → suggests `stripe.webhooks.constructEvent()`
- **GitHub push/PR** → detects `x-github-event` header → suggests verification + event switch
- **Telegram bot** → detects `update_id`, `message` → suggests bot handler
- **Monobank callback** → detects `invoiceId` + `status` → suggests payment verification
- **Notion webhook** → detects `verification_token` → suggests challenge response
- **OAuth callback** → detects `code` param → suggests token exchange
- **Payment API** → detects amount/currency → suggests payment handler
- **Health check** → detects monitoring probes → suggests status endpoint
- **Tool request** → detects curl/Postman/Insomnia user-agents

Each prediction includes confidence level (high/medium/low) and a **copy-paste handler template** — Express.js code you can drop into your project.

### 🪞 Echo/Mirror Mode
`/echo/*` or `/mirror/*` — returns exactly what was received:
- Full request headers, body, query params
- Add `?_delay=3000` to simulate slow responses (max 30s)
- Add `?_status=500` to simulate error responses
- Combine: `/echo/test?_delay=2000&_status=429` — test rate limit handling

### 📡 Webhook Catcher
Any path under `/webhook/*` — always responds 200 OK, logs everything. Point Stripe, GitHub, Telegram, or any service here during development.

### 🔑 OAuth Mock
Full OAuth2 provider:
- `GET /oauth/authorize` — redirects back with `code`, or returns JSON
- `POST /oauth/token` — returns `access_token` + `refresh_token`
- `GET /.well-known/openid-configuration` — OpenID Discovery document

### 💳 Payment Mock
- `POST /api/payment/charge` — returns valid-looking charge response (`charged: false`)
- `POST /api/payment/refund` — returns valid-looking refund response

### ✅ Domain Verification
`/.well-known/*` — responds to any verification request. Includes `assetlinks.json` for Android and OpenID config.

---

## Quick Start

### Run locally
```bash
npm install
node index.js
# Open http://localhost:3000/inspector
```

### Docker
```bash
docker build -t phantom-artifact .
docker run -p 3000:3000 phantom-artifact
```

### Deploy to Render
Push to GitHub → Render auto-deploys from `master`.

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/inspector` | Live request inspector UI |
| GET | `/inspector/events` | SSE stream for inspector |
| ALL | `/echo/*`, `/mirror/*` | Echo/mirror mode |
| GET | `/identity` | Server info + feature list |
| GET | `/health` | Status + uptime |
| GET | `/logs` | Last 50 logged requests |
| ALL | `/webhook/*` | Webhook receiver (always 200 OK) |
| GET | `/oauth/authorize` | OAuth2 authorize |
| POST | `/oauth/token` | OAuth2 token exchange |
| POST | `/api/payment/charge` | Payment mock |
| POST | `/api/payment/refund` | Refund mock |
| GET | `/.well-known/*` | Domain verification |
| ALL | `/*` | Catch-all (logs + 200 OK + predict) |

---

## Usage Examples

```bash
# Send a Stripe-like webhook and watch it in /inspector
curl -X POST https://phantom-artifact.duckdns.org/webhook/stripe \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: test_sig" \
  -d '{"type":"payment_intent.succeeded","data":{"object":{"amount":2000}}}'

# Echo with simulated delay and error status
curl https://phantom-artifact.duckdns.org/echo/api/users?_delay=2000&_status=503

# Test your OAuth callback handling
curl "https://phantom-artifact.duckdns.org/oauth/authorize?redirect_uri=http://localhost:8080/callback&state=xyz"

# Mirror a complex request
curl -X POST https://phantom-artifact.duckdns.org/mirror \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test123" \
  -H "X-Custom-Header: hello" \
  -d '{"user":"test","action":"create"}'

# Use as payment gateway stub in .env
PAYMENT_GATEWAY_URL=https://phantom-artifact.duckdns.org/api/payment
```

---

## ETH Layer

Deploy `PhantomSink.sol` via CREATE2 for deterministic on-chain identity. The contract:
- Accepts any ETH and tokens (no withdraw)
- Returns `"phantom-artifact-v1"` on `identity()`
- Claims to support any interface via `supportsInterface()`

`PhantomFactory.sol` deploys sinks with predictable addresses via CREATE2 — use `computeAddress(salt)` to know the address before deployment.

---

## Live Instances

| Layer | URL | Status |
|-------|-----|--------|
| Render | [phantom-artifact.onrender.com](https://phantom-artifact.onrender.com/inspector) | Live |
| Duck DNS | [phantom-artifact.duckdns.org](https://phantom-artifact.duckdns.org/inspector) | DNS → Render |
| GitHub | [ErgafAndTom/phantom-artifact](https://github.com/ErgafAndTom/phantom-artifact) | Auto-deploy |

---

## Philosophy

Originally conceived as a "universal identity" that could log in anywhere with `1/1`. That idea hit architectural walls — external services don't accept arbitrary OAuth providers, and credentials without email verification are useless on serious platforms.

What survived and grew: the **catch-all + predict** approach. Instead of trying to be an identity that gets past other people's walls, Phantom became a tool that **receives everything that comes at your walls** and helps you understand it.

> v1: "I want to enter any door" → hit every lock
> v2: "I'll be the door that accepts everyone" → actually useful
