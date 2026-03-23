# Phantom Artifact — Ничейный Подставной Артефакт

> Концепт: валидный ETH-аккаунт + домен + API-endpoint, который можно подставлять куда угодно как "ничейную" идентичность.

---

## Суть идеи

**Phantom Artifact** — это набор связанных между собой сущностей, которые:
- Выглядят валидно для любого сервиса/протокола/коннектора
- Не принадлежат никому (или принадлежат "всем")
- Могут подставляться в любое место, где требуется адрес/аккаунт/эндпоинт
- Работают как "чёрная дыра" — принимают всё, не отвечают ничем осмысленным (или отвечают минимально)

### Аналогии из реального мира
- `/dev/null` в Unix — принимает всё, ничего не возвращает
- `0.0.0.0` — "любой адрес" в сетях
- `example.com` (RFC 2606) — зарезервированный домен для примеров
- `0x0000...dead` — burn address в ETH

---

## Архитектура: Три слоя артефакта

### Слой 1: ETH Identity (on-chain)

**Вариант A: Детерминистический адрес через CREATE2**

```
Адрес = keccak256(0xff + deployer + salt + keccak256(bytecode))[12:]
```

Контракт-"чёрная дыра":
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title PhantomSink — ничейный контракт-приёмник
/// @notice Принимает любые ETH и токены. Никто не может вывести.
/// @dev Нет owner, нет admin, нет withdraw. Всё что входит — остаётся навсегда.
contract PhantomSink {
    
    // Принимает ETH
    receive() external payable {}
    fallback() external payable {}
    
    // Принимает любой вызов — молча проглатывает
    // fallback уже обрабатывает это
    
    // "Идентичность" — возвращает фиксированную строку
    function identity() external pure returns (string memory) {
        return "phantom-artifact-v1";
    }
    
    // Имитация ERC-165 — говорит что "поддерживает" любой интерфейс
    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
    
    // Имитация ERC-721 — чтобы проходить валидацию NFT-маркетплейсов
    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }
    
    function ownerOf(uint256) external pure returns (address) {
        return address(0);
    }
}
```

**Вариант B: Предвычисленный EOA (burn-style)**

Сгенерировать адрес, опубликовать приватный ключ → ничейный аккаунт.

```javascript
// Генерация "ничейного" кошелька — ключ публикуется, значит аккаунт ничей
const { ethers } = require('ethers');

const wallet = ethers.Wallet.createRandom();
console.log(`Address: ${wallet.address}`);
console.log(`Private Key: ${wallet.privateKey}`);
console.log(`Mnemonic: ${wallet.mnemonic.phrase}`);

// ВАЖНО: этот ключ ПУБЛИКУЕТСЯ — значит любой может использовать адрес
// Это делает его "ничейным" — как /dev/null
```

**Вариант C: Vanity Address для узнаваемости**

Адрес вида `0xDEAD...`, `0x0000...`, `0xFFFF...` — чтобы визуально было видно что это "phantom".

---

### Слой 2: Домен / DNS Identity

Домен, который:
- Отвечает 200 OK на любой путь
- Имеет валидный SSL
- Возвращает минимальный JSON на API-запросы
- Работает как webhook-приёмник

```
phantom.example.tld
├── /           → 200 OK, HTML с описанием
├── /api/*      → 200 OK, {"status": "ok", "phantom": true}
├── /webhook/*  → 200 OK, логирует payload
├── /.well-known/  → валидные конфигурации
│   ├── openid-configuration
│   ├── assetlinks.json
│   └── apple-app-site-association
└── /oauth/*    → минимальный OAuth flow (возвращает dummy token)
```

---

### Слой 3: API / Service Identity

Сервис, который имитирует любой коннектор:

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// Принимает ВСЁ — любой метод, любой путь
app.all('*', (req, res) => {
    const log = {
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        headers: req.headers,
        body: req.body,
        query: req.query,
        ip: req.ip
    };
    
    // Логируем что пришло (honeypot-режим)
    console.log(JSON.stringify(log));
    
    // Отвечаем валидно
    res.json({
        status: "ok",
        phantom: true,
        echo: {
            method: req.method,
            path: req.path
        }
    });
});

app.listen(3000);
```

---

## Use Cases: Куда подставлять

### 1. Webhook-приёмник для тестирования

**Проблема:** Настраиваешь интеграцию (Stripe, GitHub, Telegram Bot) — нужен URL для webhook.

**Решение:** Подставляешь `https://phantom.example.tld/webhook/stripe` — получаешь логи всех событий, сервис валидно отвечает 200 OK.

```
Stripe Dashboard → Webhook URL → https://phantom.tld/webhook/stripe
GitHub Repo → Settings → Webhooks → https://phantom.tld/webhook/github
Telegram Bot API → setWebhook → https://phantom.tld/webhook/tg
```

### 2. OAuth Redirect / Callback

**Проблема:** Регистрируешь OAuth приложение — нужен redirect_uri.

**Решение:** `https://phantom.tld/oauth/callback` — принимает code, логирует, показывает.

### 3. ETH-адрес как "заглушка" в смарт-контрактах

**Проблема:** В контракте нужен адрес получателя fee/royalty/treasury — но пока нет реального.

**Решение:** PhantomSink контракт — валидный адрес, принимает всё, вывести нельзя. Позже можно заменить через proxy.

```solidity
// В конструкторе NFT контракта
address public feeReceiver = 0xPhantomSinkAddress;
```

### 4. Коннектор-заглушка для ERP / интеграций

**Проблема:** ERP система требует настроенный платёжный шлюз, но он ещё не готов.

**Решение:** API phantom отвечает валидными ответами:

```json
POST /api/payment/charge
→ {"status": "ok", "transaction_id": "phantom-001", "charged": false}

POST /api/payment/refund  
→ {"status": "ok", "refund_id": "phantom-002", "refunded": false}
```

### 5. DNS / Domain Verification

**Проблема:** Сервисы требуют подтвердить домен через `.well-known`.

**Решение:** Phantom-домен отвечает на любой `.well-known` путь валидным JSON.

### 6. Исследовательский honeypot

**Проблема:** Хочешь понять, кто и что шлёт на определённый адрес/endpoint.

**Решение:** Phantom логирует ВСЁ:
- Какие IP стучатся
- Какие payload'ы приходят
- Какие заголовки отправляют
- Как часто и в какое время

### 7. Тестирование MITM-сценариев (как в анализе Telega)

**Проблема:** Хочешь проверить, подменяет ли приложение endpoint'ы.

**Решение:** Ставишь PhantomSink как "target" — если приложение коннектится к нему вместо оригинала, значит идёт подмена (аналог теста из dontusetelega.lol).

### 8. Placeholder в CI/CD pipelines

```yaml
# .env.test
PAYMENT_GATEWAY_URL=https://phantom.tld/api/payment
ANALYTICS_ENDPOINT=https://phantom.tld/api/analytics
WEBHOOK_URL=https://phantom.tld/webhook/ci
ETH_TREASURY=0xPhantomSinkAddress
```

---

## Продвинутый вариант: Phantom Protocol

Протокол на базе ERC-4337 (Account Abstraction), который создаёт "ничейные" аккаунты программно:

```
PhantomFactory (CREATE2)
├── deploy(salt) → PhantomAccount
│   ├── receive() ✓ (принимает ETH)
│   ├── execute() ✗ (нет владельца)
│   ├── identity() → "phantom-v1-{salt}"
│   └── supportsInterface() → true (имитирует всё)
│
├── computeAddress(salt) → предвычислить адрес ДО деплоя
│   (counterfactual — адрес существует "виртуально")
│
└── registry: salt → deployed address
```

Ключевая фича — **counterfactual existence**: адрес можно использовать ДО деплоя контракта. CREATE2 гарантирует, что когда контракт будет задеплоен, он окажется именно по этому адресу.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

contract PhantomFactory {
    event PhantomDeployed(bytes32 indexed salt, address indexed phantom);
    
    mapping(bytes32 => address) public registry;
    
    function deploy(bytes32 salt) external returns (address) {
        PhantomSink phantom = new PhantomSink{salt: salt}();
        address addr = address(phantom);
        registry[salt] = addr;
        emit PhantomDeployed(salt, addr);
        return addr;
    }
    
    function computeAddress(bytes32 salt) external view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(type(PhantomSink).creationCode)
            )
        );
        return address(uint160(uint256(hash)));
    }
}
```

---

## Связка всех слоёв

```
┌─────────────────────────────────────────────┐
│              PHANTOM ARTIFACT               │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ ETH Layer│  │DNS Layer │  │API Layer │  │
│  │          │  │          │  │          │  │
│  │ PhantomS │←─│phantom.  │←─│Express   │  │
│  │ ink.sol  │  │tld       │  │catch-all │  │
│  │          │  │          │  │          │  │
│  │ CREATE2  │  │*.well-   │  │/webhook  │  │
│  │ Factory  │  │known     │  │/oauth    │  │
│  │          │  │          │  │/api      │  │
│  └──────────┘  └──────────┘  └──────────┘  │
│       │              │              │       │
│       └──────────────┴──────────────┘       │
│                     │                       │
│              Unified Identity:              │
│         ENS ←→ Domain ←→ API endpoint       │
│                                             │
│  Принцип: принимает всё, не владеет ничем,  │
│  логирует всё, валиден везде               │
│                                             │
└─────────────────────────────────────────────┘
```

### ENS как связующее звено

```
phantom-artifact.eth
├── addr(60)  → PhantomSink contract address
├── text.url  → https://phantom.tld
├── text.description → "Universal phantom identity"
├── contenthash → IPFS hash страницы-описания
└── text.email → phantom@phantom.tld
```

---

## Quick Start: Минимальный рабочий прототип за 10 минут

### Шаг 1: Ничейный ETH-адрес

```bash
# Генерируем кошелёк, публикуем ключ → он становится "ничейным"
node -e "
const w = require('ethers').Wallet.createRandom();
console.log('ADDRESS:', w.address);
console.log('PRIVATE KEY:', w.privateKey);
console.log('--- Опубликуй ключ чтобы сделать адрес ничейным ---');
"
```

### Шаг 2: Catch-all API

```bash
mkdir phantom-api && cd phantom-api
npm init -y
npm install express

cat > index.js << 'EOF'
const express = require('express');
const fs = require('fs');
const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const LOG_FILE = './phantom.log';

app.all('*', (req, res) => {
    const entry = {
        t: new Date().toISOString(),
        m: req.method,
        p: req.path,
        q: req.query,
        h: { 'user-agent': req.headers['user-agent'], 'content-type': req.headers['content-type'] },
        b: req.body,
        ip: req.ip
    };
    
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
    
    // Адаптивный ответ
    if (req.path.includes('oauth')) {
        return res.json({ access_token: 'phantom_token_' + Date.now(), token_type: 'bearer', expires_in: 3600 });
    }
    if (req.path.includes('webhook')) {
        return res.json({ received: true, id: 'evt_phantom_' + Date.now() });
    }
    if (req.path.includes('.well-known')) {
        return res.json({ status: 'verified' });
    }
    if (req.path.includes('payment')) {
        return res.json({ status: 'ok', transaction_id: 'tx_phantom_' + Date.now(), success: true });
    }
    
    res.json({ status: 'ok', phantom: true, path: req.path });
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Phantom API listening on :' + (process.env.PORT || 3000));
});
EOF

node index.js
```

### Шаг 3: Подставляй куда нужно

```bash
# Тест webhook
curl -X POST http://localhost:3000/webhook/stripe \
  -H "Content-Type: application/json" \
  -d '{"event": "payment.completed", "amount": 100}'

# Тест OAuth
curl http://localhost:3000/oauth/callback?code=test123

# Тест payment gateway
curl -X POST http://localhost:3000/api/payment/charge \
  -H "Content-Type: application/json" \
  -d '{"amount": 50, "currency": "UAH"}'

# Смотрим логи
cat phantom.log | jq .
```

---

## Источники и вдохновение

- [Анализ MITM в Telega](https://dontusetelega.lol/analysis) — как подмена endpoint'ов + ключей создаёт полный перехват
- [ERC-5564: Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564) — приватные адреса-получатели
- [ERC-4337: Account Abstraction](https://www.quicknode.com/guides/ethereum-development/wallets/account-abstraction-and-erc-4337) — программируемые аккаунты
- [CREATE2 Deterministic Deployment](https://learnblockchain.cn/docs/foundry/i18n/en/tutorials/create2-tutorial.html) — предвычисление адресов
- [Honeypot Contracts (USENIX)](https://www.usenix.org/system/files/sec19-torres.pdf) — паттерны ловушек в ETH
- [Burner Wallets](https://www.ccn.com/education/crypto/burner-wallets-defi-nft-trading/) — одноразовые кошельки
