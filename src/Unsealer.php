<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use SensitiveParameter;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;
use Wenbo\ReqResCrypto\Core\Exceptions\KeyException;
use Wenbo\ReqResCrypto\Core\Exceptions\ReplayException;

final class Unsealer implements UnsealerInterface
{
    private const VERSION = 1;
    private const EXCHANGE_PUBKEY_LEN = SODIUM_CRYPTO_KX_PUBLICKEYBYTES; // 32
    private const TIMESTAMP_LEN = 8;
    private const NONCE_LEN = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    private const HEADER_LEN = 1 + self::EXCHANGE_PUBKEY_LEN + self::TIMESTAMP_LEN; // 41
    private const MIN_WIRE_LEN = self::HEADER_LEN + self::NONCE_LEN + 1; // 54

    /** 默认时间容差（秒） */
    private int $timeWindow;

    /** 上一次 unseal 从 wire 中提取的客户端交换公钥（二进制） */
    private ?string $clientExchangePubKey = null;

    public function __construct(
        private KeyExchange $keyExchange,
        private ServerKeyProviderInterface $keyProvider,
        private NonceStoreInterface $nonceStore,
        private SerializerInterface $serializer,
        int $timeWindow = 300,
    ) {
        $this->timeWindow = $timeWindow;
    }

    /**
     * 返回上一次 unseal 从 wire 提取的客户端交换公钥（二进制）。
     */
    public function getClientExchangePubKey(): ?string
    {
        return $this->clientExchangePubKey;
    }

    /**
     * 解密请求 wire format，防重放。
     *
     * Wire format: version(1) || exchange_pubkey(32) || timestamp(8) || nonce(12) || ciphertext
     *
     * 客户端公钥直接嵌入 wire 中，服务端无需查询 KeyProvider 即可完成 ECDH。
     *
     * @param string $wire 二进制 wire format
     * @return mixed       原始数据
     *
     * @throws CryptoException|ReplayException|KeyException
     */
    public function unseal(string $wire): mixed
    {
        $this->clientExchangePubKey = null;

        if (strlen($wire) < self::MIN_WIRE_LEN) {
            throw new CryptoException('无效的请求体: 长度不足');
        }

        $offset = 0;

        // Version
        $version = ord($wire[$offset]);
        $offset += 1;
        if ($version !== self::VERSION) {
            throw new CryptoException(sprintf('不支持的协议版本: %d', $version));
        }

        // 客户端交换公钥（32 字节，直接嵌入 wire）
        $clientExchangePublicKey = mb_substr($wire, $offset, self::EXCHANGE_PUBKEY_LEN, '8bit');
        $this->clientExchangePubKey = $clientExchangePublicKey;
        $offset += self::EXCHANGE_PUBKEY_LEN;

        // Timestamp
        $timestampBytes = mb_substr($wire, $offset, self::TIMESTAMP_LEN, '8bit');
        $timestamp = unpack('P', $timestampBytes)[1];

        $now = time();
        if ($timestamp > $now + $this->timeWindow) {
            throw ReplayException::futureTimestamp();
        }
        if ($timestamp < $now - $this->timeWindow) {
            throw ReplayException::expiredTimestamp();
        }

        // Body: nonce + ciphertext
        $body = mb_substr($wire, self::HEADER_LEN, null, '8bit');

        // Nonce 防重放：原子写入，避免 check-then-store 竞态
        $nonce = mb_substr($body, 0, self::NONCE_LEN, '8bit');
        if (! $this->nonceStore->store($nonce, $this->timeWindow)) {
            throw ReplayException::duplicateNonce();
        }

        // 获取当前密钥（一次调用获取所有字段，避免 N+1 查询）
        $currentKey = $this->keyProvider->getCurrentKey();
        if ($currentKey === null) {
            throw KeyException::notFound('current');
        }

        // ECDH：服务端 X25519 私钥 + 客户端 X25519 公钥
        $sharedKey = $this->keyExchange->computeSharedKey(
            $currentKey->exchangeSecretKey,
            $clientExchangePublicKey,
        );

        $encrypter = new Encrypter($sharedKey);
        $payload = $encrypter->decrypt($body);

        return $this->serializer->unserialize($payload);
    }
}
