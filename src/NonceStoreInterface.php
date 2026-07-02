<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

interface NonceStoreInterface
{
    /**
     * 检查 nonce 是否已使用。
     */
    public function exists(string $nonce): bool;

    /**
     * 原子写入 nonce，返回是否首次存储。
     *
     * 高并发下必须用"不存在则写入"的原子操作（如 Cache::add、Redis SET NX），
     * 避免 check-then-store 竞态导致重放攻击绕过。
     *
     * @return bool true = 首次存储成功，false = nonce 已存在（重复）
     */
    public function store(string $nonce, int $ttlSeconds): bool;
}
