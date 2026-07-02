<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

interface ServerKeyProviderInterface
{
    /**
     * 获取当前活跃密钥（整行，含所有字段）。
     * 无可用密钥时返回 null。
     */
    public function getCurrentKey(): ?ServerKey;

    /**
     * 获取 pre_issued 状态的待轮换密钥（整行）。
     * 无待轮换密钥时返回 null。
     */
    public function getPreIssuedKey(): ?ServerKey;
}
