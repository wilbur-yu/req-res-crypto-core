<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core\Exceptions;

class SignatureException extends CryptoException
{
    public static function verificationFailed(): self
    {
        return new self('签名验证失败');
    }

}
