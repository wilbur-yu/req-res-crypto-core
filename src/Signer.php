<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use SensitiveParameter;
use SodiumException;
use Wenbo\ReqResCrypto\Core\Exceptions\SignatureException;

final readonly class Signer
{
    private string $secretKey;
    private string $publicKey;

    /**
     * @throws SignatureException
     */
    public function __construct(
        #[SensitiveParameter] string $secretKey,
        string $publicKey,
    ) {
        if ($publicKey === '') {
            throw SignatureException::verificationFailed();
        }

        $this->secretKey = $secretKey;
        $this->publicKey = $publicKey;
    }

    /**
     * Ed25519 签名（RFC 8032 格式）。
     *
     * @throws SignatureException
     */
    public function sign(#[SensitiveParameter] string $message): string
    {
        if ($this->secretKey === '') {
            throw new SignatureException('签名需要私钥，当前实例仅可用于验签');
        }

        try {
            return sodium_crypto_sign_detached($message, $this->secretKey);
        } catch (SodiumException $e) {
            throw new SignatureException('签名失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Ed25519 验签。
     *
     * @throws SignatureException
     */
    public function verify(string $message, string $signature): void
    {
        try {
            $valid = sodium_crypto_sign_verify_detached($signature, $message, $this->publicKey);
        } catch (SodiumException $e) {
            throw new SignatureException('验签过程异常: ' . $e->getMessage(), 0, $e);
        }

        if (!$valid) {
            throw SignatureException::verificationFailed();
        }
    }
}
