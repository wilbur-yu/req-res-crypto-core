<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

interface UnsealerInterface
{
    /**
     * 解封 wire format 并防重放，返回原始数据。
     *
     * 客户端 X25519 公钥嵌入 wire 中直接读取，
     * 响应端中间件通过 getClientExchangePubKey() 获取用于加密响应。
     */
    public function unseal(string $wire): mixed;

    /**
     * 上一次 unseal 调用中从 wire 提取的客户端交换公钥（二进制）。
     *
     * 公钥嵌入 wire format 中直接读取，
     * 服务端中间件通过此方法获取客户端公钥用于加密响应。
     */
    public function getClientExchangePubKey(): ?string;
}
