<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use SensitiveParameter;
use Wenbo\ReqResCrypto\Core\Exceptions\KeyException;

final readonly class KeyPair
{
    private function __construct(
        public string $signPublicKey,
        #[SensitiveParameter]
        public string $signSecretKey,
        public string $exchangePublicKey,
        #[SensitiveParameter]
        public string $exchangeSecretKey,
    ) {
    }

    /**
     * 生成 Ed25519 签名密钥对 + X25519 交换密钥对。
     *
     * @throws KeyException
     */
    public static function generate(): self
    {
        try {
            $signKeyPair = sodium_crypto_sign_keypair();
            $exchangeKeyPair = sodium_crypto_box_keypair();
        } catch (\SodiumException $e) {
            throw KeyException::invalidKey('生成失败: ' . $e->getMessage());
        }

        return new self(
            signPublicKey: sodium_crypto_sign_publickey($signKeyPair),
            signSecretKey: sodium_crypto_sign_secretkey($signKeyPair),
            exchangePublicKey: sodium_crypto_box_publickey($exchangeKeyPair),
            exchangeSecretKey: sodium_crypto_box_secretkey($exchangeKeyPair),
        );
    }

    /**
     * 从已有密钥字符串恢复 KeyPair。
     *
     * @throws KeyException
     */
    public static function fromStrings(
        string $signPublicKey,
        #[SensitiveParameter] string $signSecretKey,
        string $exchangePublicKey,
        #[SensitiveParameter] string $exchangeSecretKey,
    ): self {
        return new self(
            signPublicKey: $signPublicKey,
            signSecretKey: $signSecretKey,
            exchangePublicKey: $exchangePublicKey,
            exchangeSecretKey: $exchangeSecretKey,
        );
    }

    /**
     * 取公钥指纹前 4 字节（hex），用作 Key ID。
     */
    public function keyId(): string
    {
        return bin2hex(mb_substr($this->signPublicKey, 0, 4, '8bit'));
    }
}
