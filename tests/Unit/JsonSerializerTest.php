<?php

declare(strict_types=1);

use Wenbo\ReqResCrypto\Core\JsonSerializer;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;

// 序列化/反序列化
test('serialize and unserialize round trip', function () {
    $s = new JsonSerializer();

    $data = ['user' => 'alice', 'ts' => time(), 'nested' => ['x' => 1.5]];
    $encoded = $s->serialize($data);
    $decoded = $s->unserialize($encoded);

    expect($decoded)->toBe($data);
});

// 空数组
test('empty array round trip', function () {
    $s = new JsonSerializer();
    $decoded = $s->unserialize($s->serialize([]));

    expect($decoded)->toBe([]);
});

// 整数、浮点、字符串、布尔、null
test('scalar values round trip', function () {
    $s = new JsonSerializer();

    expect($s->unserialize($s->serialize(42)))->toBe(42);
    expect($s->unserialize($s->serialize(3.14)))->toBe(3.14);
    expect($s->unserialize($s->serialize('hello')))->toBe('hello');
    expect($s->unserialize($s->serialize(true)))->toBe(true);
    expect($s->unserialize($s->serialize(null)))->toBeNull();
});

// 大整数 + 嵌套深度
test('deeply nested structure', function () {
    $s = new JsonSerializer();
    $data = json_decode('{"a":{"b":{"c":{"d":{"e":"deep"}}}}}', true);

    $result = $s->unserialize($s->serialize($data));
    expect($result)->toBe($data);
});

// 对抗式：无效 JSON 字符串
test('unserialize rejects invalid JSON', function () {
    $s = new JsonSerializer();

    expect(fn () => $s->unserialize('{broken'))
        ->toThrow(CryptoException::class);
});
