<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use SensitiveParameter;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;

/**
 * AEAD 加密器，将己方 X25519 公钥嵌入 wire，接收方直接读取做 ECDH。
 */
final readonly class Sealer implements SealerInterface
{
    /**
     * Wire format 常量。
     */
    private const VERSION = 1;

    private const EXCHANGE_PUBKEY_LEN = SODIUM_CRYPTO_KX_PUBLICKEYBYTES; // 32
    private const TIMESTAMP_LEN = 8;
    private const NONCE_LEN = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    public function __construct(
        private KeyExchange $keyExchange,
        private SerializerInterface $serializer,
    ) {
    }

    /**
     * AEAD 加密，己方交换公钥嵌入 wire。
     *
     * Wire format: version(1) || exchange_pubkey(32) || timestamp(8) || nonce(12) || ciphertext
     *
     * @param string $exchangePublicKey    己方 X25519 交换公钥（hex）
     * @param string $exchangeSecretKey    己方 X25519 交换私钥
     * @param string $theirExchangePubKey  对方 X25519 交换公钥
     * @param mixed  $plaintext            任意可序列化数据
     *
     * @return string 二进制 wire format
     */
    public function seal(
        string $exchangePublicKey,
        #[SensitiveParameter] string $exchangeSecretKey,
        string $theirExchangePubKey,
        mixed $plaintext,
    ): string {
        $sharedKey = $this->keyExchange->computeSharedKey($exchangeSecretKey, $theirExchangePubKey);
        $encrypter = new Encrypter($sharedKey);

        $payload = $this->serializer->serialize($plaintext);
        $timestamp = time();

        $body = $encrypter->encrypt($payload);

        return pack('C', self::VERSION)
            . hex2bin($exchangePublicKey)
            . pack('P', $timestamp)
            . $body;
    }
}
