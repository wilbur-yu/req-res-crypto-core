# req-res-crypto-core

PHP 请求 / 响应加密核心库，零框架依赖。基于 AEAD 加密（XChaCha20-Poly1305）+ X25519 ECDH 密钥交换。

## 密码方案

| 层次 | 算法 | 用途 |
| --- | --- | --- |
| 密钥协商 | X25519 ECDH | 客户端与服务端协商共享密钥 |
| 加密 | XChaCha20-Poly1305 IETF AEAD | 加解密请求/响应体 |

AEAD 内建的 Poly1305 MAC 提供数据认证，无需额外的 Ed25519 签名。

## Wire Format

唯一加密格式（请求和响应共用）：

```
┌─────────┬───────────────────┬───────────┬───────────────────────┐
│ version │ exchange_pubkey   │ timestamp │ nonce(12) + ciphertext│
│  1 byte │     32 bytes      │  8 bytes  │        变长            │
└─────────┴───────────────────┴───────────┴───────────────────────┘
```

- **version**: 固定 `0x01`
- **exchange_pubkey**: 己方 X25519 公钥，直接嵌入 wire
- **timestamp**: Unix 时间戳（小端序），防重放时间窗口校验
- **body**: `nonce(12) || ciphertext`，XChaCha20-Poly1305 IETF AEAD

最小有效长度：`1 + 32 + 8 + 12 + 1 = 54` 字节。

## 安装

```bash
composer require wenbo/req-res-crypto-core
```

依赖：PHP >= 8.3，`ext-sodium`。

## 核心 API

### Sealer（加密器）

```php
use Wenbo\ReqResCrypto\Core\Sealer;
use Wenbo\ReqResCrypto\Core\KeyExchange;
use Wenbo\ReqResCrypto\Core\JsonSerializer;

$sealer = new Sealer(
    new KeyExchange(),
    new JsonSerializer(),
);

$wire = $sealer->seal(
    exchangePublicKey: bin2hex($myExchangePubKey),   // 己方 X25519 公钥（hex）
    exchangeSecretKey: $myExchangeSecretKey,          // 己方 X25519 私钥
    theirExchangePubKey: $theirExchangePubKey,       // 对方 X25519 公钥
    plaintext: ['action' => 'query', 'id' => 42],
);

// $wire 为二进制 wire format，传输前应 base64 编码
$payload = base64_encode($wire);
```

### Unsealer（解密器）

```php
use Wenbo\ReqResCrypto\Core\Unsealer;
use Wenbo\ReqResCrypto\Core\KeyExchange;
use Wenbo\ReqResCrypto\Core\JsonSerializer;

$unsealer = new Unsealer(
    keyExchange: new KeyExchange(),
    keyProvider: $keyProvider,       // 实现 ServerKeyProviderInterface
    nonceStore: $nonceStore,         // 实现 NonceStoreInterface
    serializer: new JsonSerializer(),
    timeWindow: 300,                 // 时间容差（秒），默认 300
);

$data = $unsealer->unseal(base64_decode($wire));

// 获取客户端 X25519 公钥（用于响应加密）
$clientPubKey = $unsealer->getClientExchangePubKey();
```

解密流程：
1. 解析 version、exchange_pubkey、timestamp
2. 时间窗口校验（默认 ±300 秒）
3. Nonce 去重（通过 `NonceStoreInterface`）
4. 获取服务端私钥，计算 ECDH 共享密钥
5. XChaCha20-Poly1305 解密
6. JSON 反序列化

### KeyPair（密钥对生成）

```php
use Wenbo\ReqResCrypto\Core\KeyPair;

$keyPair = KeyPair::generate();

// 属性（均为 32 字节二进制）
$keyPair->signPublicKey;      // Ed25519 签名公钥
$keyPair->signSecretKey;      // Ed25519 签名私钥
$keyPair->exchangePublicKey;  // X25519 交换公钥
$keyPair->exchangeSecretKey;  // X25519 交换私钥
$keyPair->keyId();            // 前 4 字节 hex，用作 Key ID
```

### ServerKeyProviderInterface（服务端密钥管理）

```php
interface ServerKeyProviderInterface
{
    public function getCurrentKeyId(): ?string;
    public function getSignSecretKey(string $keyId): ?string;
    public function getExchangeSecretKey(string $keyId): ?string;
    public function getSignPublicKey(string $keyId): ?string;
    public function getExchangePublicKey(string $keyId): ?string;
    public function getPreIssuedKeyId(): ?string;
}
```

### NonceStoreInterface（防重放）

```php
interface NonceStoreInterface
{
    public function exists(string $nonce): bool;
    public function store(string $nonce, int $ttlSeconds): void;
}
```

### 异常体系

| 异常 | 父类 | 说明 |
| --- | --- | --- |
| `CryptoException` | `RuntimeException` | 加解密失败、消息格式错误等 |
| `KeyException` | `CryptoException` | 密钥未找到、密钥无效 |
| `ReplayException` | `CryptoException` | 重放检测（过期/未来时间戳、重复 Nonce） |

## 密钥轮换

参见框架适配包文档（Laravel / Hyperf），核心包仅定义 `ServerKeyProviderInterface`。

## 前端对接

参见 `@wenbo/req-res-crypto-js` npm 包。客户端每次请求动态生成 X25519 密钥对（~0.05ms），公钥嵌入 wire，用完即弃。
