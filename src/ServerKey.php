<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

/**
 * 服务端密钥值对象，承载一行密钥记录的全部字段。
 *
 * 所有密钥字段均为二进制格式（非 hex），keyId 为 8 字符 hex 标识符。
 */
final readonly class ServerKey
{
    public function __construct(
        public string $keyId,
        public string $signSecretKey,
        public string $signPublicKey,
        public string $exchangeSecretKey,
        public string $exchangePublicKey,
    ) {
    }
}
