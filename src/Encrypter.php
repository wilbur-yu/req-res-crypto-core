<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use SensitiveParameter;
use SodiumException;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;

final readonly class Encrypter
{
    private string $key;

    /**
     * @throws CryptoException
     */
    public function __construct(
        #[SensitiveParameter]
        string $sharedKey,
    ) {
        if ($sharedKey === '') {
            throw new CryptoException('加密密钥不能为空');
        }
        $this->key = $sharedKey;
    }

    /**
     * XChaCha20-Poly1305 IETF AEAD 加密。
     * 返回格式: nonce(24字节) || ciphertext
     */
    public function encrypt(#[SensitiveParameter] string $plaintext): string
    {
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                '',
                $nonce,
                $this->key,
            );
        } catch (SodiumException $e) {
            throw new CryptoException('加密失败: ' . $e->getMessage(), 0, $e);
        }

        return $nonce . $ciphertext;
    }

    /**
     * XChaCha20-Poly1305 IETF AEAD 解密。
     * 输入格式: nonce(24字节) || ciphertext
     */
    public function decrypt(string $payload): string
    {
        $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

        if (strlen($payload) < $nonceLen) {
            throw new CryptoException('密文太短');
        }

        $nonce = mb_substr($payload, 0, $nonceLen, '8bit');
        $ciphertext = mb_substr($payload, $nonceLen, null, '8bit');

        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                '',
                $nonce,
                $this->key,
            );
        } catch (SodiumException $e) {
            throw new CryptoException('解密失败: 密钥不匹配或数据已损坏', 0, $e);
        }

        if ($plaintext === false) {
            throw new CryptoException('解密失败: 密钥不匹配或数据已损坏');
        }

        return $plaintext;
    }
}
