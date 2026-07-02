<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core\Exceptions;

class ReplayException extends CryptoException
{
    public static function duplicateNonce(): self
    {
        return new self('检测到重放攻击: nonce 已使用');
    }

    public static function expiredTimestamp(): self
    {
        return new self('请求已过期，时间戳超出允许窗口');
    }

    public static function futureTimestamp(): self
    {
        return new self('时间戳来自未来，请检查时钟同步');
    }
}
