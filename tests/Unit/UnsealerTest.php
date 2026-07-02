<?php

declare(strict_types=1);

use Wenbo\ReqResCrypto\Core\KeyPair;
use Wenbo\ReqResCrypto\Core\KeyExchange;
use Wenbo\ReqResCrypto\Core\Sealer;
use Wenbo\ReqResCrypto\Core\Unsealer;
use Wenbo\ReqResCrypto\Core\JsonSerializer;
use Wenbo\ReqResCrypto\Core\ServerKey;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;
use Wenbo\ReqResCrypto\Core\Exceptions\ReplayException;
use Wenbo\ReqResCrypto\Core\Exceptions\KeyException;
use Wenbo\ReqResCrypto\Core\ServerKeyProviderInterface;
use Wenbo\ReqResCrypto\Core\NonceStoreInterface;

// --- 测试用桩 ---

final class InMemoryKeyProvider implements ServerKeyProviderInterface
{
    public function __construct(
        private readonly array $keys,
        private readonly ?string $currentKeyId = null,
    ) {
    }

    public function getCurrentKey(): ?ServerKey
    {
        $keyId = $this->currentKeyId ?? array_key_first($this->keys);
        if ($keyId === null || !isset($this->keys[$keyId])) {
            return null;
        }

        $k = $this->keys[$keyId];

        return new ServerKey(
            keyId: $keyId,
            signSecretKey: $k['sign_secret'] ?? '',
            signPublicKey: $k['sign'] ?? '',
            exchangeSecretKey: $k['exchange_secret'] ?? '',
            exchangePublicKey: $k['exchange'] ?? '',
        );
    }

    public function getPreIssuedKey(): ?ServerKey
    {
        return null;
    }
}

final class ArrayNonceStore implements NonceStoreInterface
{
    private array $store = [];

    public function exists(string $nonce): bool
    {
        return array_key_exists($nonce, $this->store) && $this->store[$nonce] > time();
    }

    public function store(string $nonce, int $ttlSeconds): bool
    {
        if (array_key_exists($nonce, $this->store) && $this->store[$nonce] > time()) {
            return false;
        }
        $this->store[$nonce] = time() + $ttlSeconds;
        return true;
    }
}

// --- 测试套件 ---

function buildUnsealer(KeyPair $bob, int $timeWindow = 300): Unsealer
{
    $bobKeyId = $bob->keyId();

    return new Unsealer(
        new KeyExchange(),
        new InMemoryKeyProvider([
            // Bob 作为服务端（current key），有私钥
            $bobKeyId => [
                'sign' => $bob->signPublicKey,
                'exchange' => $bob->exchangePublicKey,
                'sign_secret' => $bob->signSecretKey,
                'exchange_secret' => $bob->exchangeSecretKey,
            ],
        ], $bobKeyId),
        new ArrayNonceStore(),
        new JsonSerializer(),
        $timeWindow,
    );
}

// seal → unseal 完整闭环
test('seal and unseal round trip', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $data = ['order_id' => 'ORD-12345', 'amount' => 99.99];
    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, $data);

    $unsealer = buildUnsealer($bob);
    $result = $unsealer->unseal($wire);

    expect($result)->toBe($data);
});

// 验证 getClientExchangePubKey
test('unsealer extracts client exchange pubkey', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'x');

    $unsealer = buildUnsealer($bob);
    $unsealer->unseal($wire);

    expect($unsealer->getClientExchangePubKey())->toBe($alice->exchangePublicKey);
});

// 对抗式：截断 wire
test('unseal rejects truncated wire', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'x');
    $truncated = mb_substr($wire, 0, 10, '8bit');

    $unsealer = buildUnsealer($bob);

    expect(fn () => $unsealer->unseal($truncated))
        ->toThrow(CryptoException::class);
});

// 对抗式：篡改版本号
test('unseal rejects wrong wire version', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'x');
    $wire[0] = chr(99); // 修改版本号

    $unsealer = buildUnsealer($bob);

    expect(fn () => $unsealer->unseal($wire))
        ->toThrow(CryptoException::class);
});

// 对抗式：篡改密文（AEAD 解密应失败）
test('unseal rejects tampered ciphertext', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'real data');

    // 篡改密文中间字节
    $offset = 1 + 32 + 8 + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + 1;
    if (strlen($wire) > $offset) {
        $wire[$offset] = chr(ord($wire[$offset]) ^ 0xFF);
    }

    $unsealer = buildUnsealer($bob);

    expect(fn () => $unsealer->unseal($wire))
        ->toThrow(CryptoException::class);
});

// 对抗式：重放 nonce
test('unseal rejects replayed nonce', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'x');

    $unsealer = buildUnsealer($bob);
    $unsealer->unseal($wire); // 第一次成功

    expect(fn () => $unsealer->unseal($wire)) // 重放
        ->toThrow(ReplayException::class);
});

// 对抗式：过期时间戳
test('unseal rejects expired timestamp', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'x');

    // 手动将 timestamp 改为 epoch 0，远早于当前时间
    // timestamp 位置: 1 + 32 = 33，占 8 字节
    $tsOffset = 33;
    for ($i = 0; $i < 8; $i++) {
        $wire[$tsOffset + $i] = chr(0);
    }

    $unsealer = buildUnsealer($bob);

    expect(fn () => $unsealer->unseal($wire))
        ->toThrow(ReplayException::class);
});

// 测试无密钥时的异常
test('unsealer throws when no server key configured', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'x');

    // 用没有 key 的 provider
    $unsealer = new Unsealer(
        new KeyExchange(),
        new InMemoryKeyProvider([]),
        new ArrayNonceStore(),
        new JsonSerializer(),
    );

    expect(fn () => $unsealer->unseal($wire))
        ->toThrow(KeyException::class);
});
