<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use SensitiveParameter;
use SodiumException;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;

final readonly class KeyExchange
{
    /**
     * X25519 ECDH，返回 32 字节共享密钥用于 XChaCha20-Poly1305。
     *
     * @throws CryptoException
     */
    public function computeSharedKey(
        #[SensitiveParameter] string $mySecretKey,
        string $theirPublicKey,
    ): string {
        try {
            $shared = sodium_crypto_scalarmult($mySecretKey, $theirPublicKey);
        } catch (SodiumException $e) {
            throw new CryptoException('密钥协商失败: ' . $e->getMessage(), 0, $e);
        }

        return $shared;
    }
}
