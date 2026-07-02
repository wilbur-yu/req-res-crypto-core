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

### JsonSerializer（JSON 序列化器）

实现 `SerializerInterface`，统一请求/响应的 JSON 编解码：

```php
use Wenbo\ReqResCrypto\Core\JsonSerializer;

$serializer = new JsonSerializer();
$json = $serializer->serialize(['key' => 'value']);       // → JSON 字符串
$data = $serializer->unserialize('{"key":"value"}');       // → 关联数组
```

默认使用 `JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES` 编码，`unserialize` 前会 `json_validate` 校验。

### ServerKey（服务端密钥值对象）

`ServerKeyProviderInterface::getCurrentKey()` 的返回类型，封装一对服务端密钥：

```php
final readonly class ServerKey
{
    public string $keyId;             // 8 字符 hex
    public string $signSecretKey;     // Ed25519 签名私钥（二进制）
    public string $signPublicKey;     // Ed25519 签名公钥（二进制）
    public string $exchangeSecretKey; // X25519 交换私钥（二进制）
    public string $exchangePublicKey; // X25519 交换公钥（二进制）
}
```

### PathMatcher（路径模式匹配）

支持 `*`（单段）和 `**`（递归多段）通配符的路径匹配工具：

```php
use Wenbo\ReqResCrypto\Core\PathMatcher;

PathMatcher::matches('/api/users/123', '/api/**');   // true
PathMatcher::matches('/api/v2/list', '/api/*');      // true
PathMatcher::matches('/api/v2/x/y', '/api/*');       // false（跨段）

PathMatcher::matchesAny('/health', ['/api/**', '/health']); // true
```

框架适配包用此工具实现 `skip_routes` 配置。

### NonceStoreInterface（防重放）

```php
interface NonceStoreInterface
{
    public function exists(string $nonce): bool;

    /**
     * 原子写入 nonce，返回是否首次存储。
     * 高并发下必须用"不存在则写入"的原子操作（如 Cache::add、Redis SET NX），
     * 避免 check-then-store 竞态导致重放攻击绕过。
     *
     * @return bool true = 首次存储成功，false = nonce 已存在（重复）
     */
    public function store(string $nonce, int $ttlSeconds): bool;
}
```

### 异常体系

| 异常 | 父类 | 说明 |
| --- | --- | --- |
| `CryptoException` | `RuntimeException` | 加解密失败、消息格式错误等 |
| `KeyException` | `CryptoException` | 密钥未找到、密钥无效 |
| `ReplayException` | `CryptoException` | 重放检测（过期/未来时间戳、重复 Nonce） |

## 密钥轮换

核心包仅定义 `ServerKeyProviderInterface`，完整的密钥轮换（数据库持久化、定时 Crontab、Artisan 命令）由框架适配包提供：

- [req-res-crypto-hyperf](https://github.com/wenber-yu/req-res-crypto-hyperf) — Hyperf 适配
- [req-res-crypto-laravel](https://github.com/wenber-yu/req-res-crypto-laravel) — Laravel 适配

## 框架适配

| 框架 | 包 | 功能 |
| --- | --- | --- |
| Hyperf | [req-res-crypto-hyperf](https://github.com/wenber-yu/req-res-crypto-hyperf) | PSR-15 中间件、数据库密钥轮换、Crontab、Command 命令 |
| Laravel | [req-res-crypto-laravel](https://github.com/wenber-yu/req-res-crypto-laravel) | 中间件、Facade、注解驱动加解密、数据库密钥轮换、Artisan 命令 |

## 前端对接

前端（浏览器）客户端 [req-res-crypto-js](https://github.com/wenber-yu/req-res-crypto-js)，提供 axios / fetch 透明加解密集成。客户端每次请求动态生成 X25519 密钥对（~0.05ms），公钥嵌入 wire，用完即弃。

```bash
npm install @wenbo/req-res-crypto-js
```
