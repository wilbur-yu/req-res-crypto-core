<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use SensitiveParameter;

interface SealerInterface
{
    /**
     * AEAD 加密，己方交换公钥嵌入 wire，返回二进制 wire format。
     *
     * @param string $exchangePublicKey   己方 X25519 交换公钥（hex）
     * @param string $exchangeSecretKey   己方 X25519 交换私钥
     * @param string $theirExchangePubKey 对方 X25519 交换公钥
     * @param mixed  $plaintext           任意可序列化数据
     *
     * @return string 二进制 wire format:
     *                version(1) || exchange_pubkey(32) || timestamp(8) || nonce(12) || ciphertext
     */
    public function seal(
        string $exchangePublicKey,
        #[SensitiveParameter] string $exchangeSecretKey,
        string $theirExchangePubKey,
        mixed $plaintext,
    ): string;
}
