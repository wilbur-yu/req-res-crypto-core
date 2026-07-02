<?php

declare(strict_types=1);

use Wenbo\ReqResCrypto\Core\KeyPair;
use Wenbo\ReqResCrypto\Core\Encrypter;
use Wenbo\ReqResCrypto\Core\KeyExchange;
use Wenbo\ReqResCrypto\Core\Sealer;
use Wenbo\ReqResCrypto\Core\JsonSerializer;

// 基础 seal
test('seal produces binary wire format', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $data = ['user_id' => 42, 'action' => 'pay'];

    $wire = $sealer->seal(
        bin2hex($alice->exchangePublicKey),
        $alice->exchangeSecretKey,
        $bob->exchangePublicKey,
        $data,
    );

    // wire format 最小长度: 1 + 32 + 8 + 12 + 1 = 54
    expect(strlen($wire))->toBeGreaterThanOrEqual(54);
});

// 每次 seal 不同（nonce 随机 + timestamp）
test('seal is non-deterministic', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $w1 = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'same');
    usleep(50); // 确保时间戳不同
    $w2 = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, 'same');

    expect($w1)->not->toBe($w2);
});

// wire format 前导字节校验
test('seal wire format starts with version=1 and exchange pubkey', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $sealer = new Sealer(
        new KeyExchange(),
        new JsonSerializer(),
    );

    $wire = $sealer->seal(bin2hex($alice->exchangePublicKey), $alice->exchangeSecretKey, $bob->exchangePublicKey, ['a' => 1]);

    // Version byte == 1
    expect(ord($wire[0]))->toBe(1);

    // 交换公钥 (bytes 1-32) 匹配
    $wirePubKey = mb_substr($wire, 1, 32, '8bit');
    expect($wirePubKey)->toBe($alice->exchangePublicKey);
});
