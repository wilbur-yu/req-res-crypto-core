<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

interface SerializerInterface
{
    /**
     * 将数据序列化为字符串。
     */
    public function serialize(mixed $data): string;

    /**
     * 将字符串反序列化为原始数据。
     */
    public function unserialize(string $data): mixed;
}
