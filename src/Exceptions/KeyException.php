<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core\Exceptions;

class KeyException extends CryptoException
{
    public static function notFound(string $keyId): self
    {
        return new self(sprintf('未找到密钥: %s', $keyId));
    }

    public static function databaseError(string $reason = ''): self
    {
        $message = '密钥数据库异常';
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message);
    }

    public static function invalidKey(string $reason = ''): self
    {
        $message = '无效的密钥';
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message);
    }
}
