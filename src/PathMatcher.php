<?php

declare(strict_types=1);

namespace Wenbo\ReqResCrypto\Core;

/**
 * 路径模式匹配工具。
 *
 * 支持通配符：
 * - *   匹配不包含 / 的任意字符
 * - **  匹配任意字符（含 /），递归匹配多段
 */
final class PathMatcher
{
    /**
     * 检查路径是否匹配模式。
     *
     * @param string $path    请求路径（如 /api/users/123）
     * @param string $pattern 模式（如 /api/**, /api/*）
     */
    public static function matches(string $path, string $pattern): bool
    {
        // 双星号 ** 递归匹配多段
        if (str_contains($pattern, '**')) {
            $prefix = rtrim(str_replace('**', '', $pattern), '/');
            if ($prefix === '' || str_starts_with($path, $prefix)) {
                return true;
            }
            return false;
        }

        // 单星号 * 匹配单段
        if (str_contains($pattern, '*')) {
            $quoted = preg_quote($pattern, '#');
            $quoted = str_replace('\*', '[^/]*', $quoted);

            return (bool) preg_match('#^' . $quoted . '$#', $path);
        }

        return $path === $pattern;
    }

    /**
     * 检查路径是否匹配任意一个模式。
     *
     * @param string[] $patterns 模式列表
     */
    public static function matchesAny(string $path, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (self::matches($path, $pattern)) {
                return true;
            }
        }

        return false;
    }
}
