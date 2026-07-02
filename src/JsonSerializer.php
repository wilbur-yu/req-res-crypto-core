<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

use JsonException;

final readonly class JsonSerializer implements SerializerInterface
{
    public function serialize(mixed $data): string
    {
        try {
            return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new Exceptions\CryptoException('序列化失败: ' . $e->getMessage(), 0, $e);
        }
    }

    public function unserialize(string $data): mixed
    {
        if (!json_validate($data)) {
            throw new Exceptions\CryptoException('JSON 数据格式无效');
        }

        try {
            return json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new Exceptions\CryptoException('反序列化失败: ' . $e->getMessage(), 0, $e);
        }
    }
}
