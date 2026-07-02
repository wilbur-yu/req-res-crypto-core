<?php

declare(strict_types=1);

use Wenbo\ReqResCrypto\Core\KeyPair;
use Wenbo\ReqResCrypto\Core\KeyExchange;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;

// 基础密钥协商
test('computeSharedKey produces consistent shared key', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $ke = new KeyExchange();

    $sharedA = $ke->computeSharedKey($alice->exchangeSecretKey, $bob->exchangePublicKey);
    $sharedB = $ke->computeSharedKey($bob->exchangeSecretKey, $alice->exchangePublicKey);

    expect($sharedA)->not->toBeEmpty();
    expect($sharedA)->toBe($sharedB);
});

// 每次协商可重复
test('computeSharedKey is deterministic for same inputs', function () {
    $alice = KeyPair::generate();
    $bob = KeyPair::generate();

    $ke = new KeyExchange();

    $shared1 = $ke->computeSharedKey($alice->exchangeSecretKey, $bob->exchangePublicKey);
    $shared2 = $ke->computeSharedKey($alice->exchangeSecretKey, $bob->exchangePublicKey);

    expect($shared1)->toBe($shared2);
});

// 对抗式：不同私钥产生不同共享密钥
test('different private keys produce different shared keys', function () {
    $alice1 = KeyPair::generate();
    $alice2 = KeyPair::generate();
    $bob = KeyPair::generate();

    $ke = new KeyExchange();

    $shared1 = $ke->computeSharedKey($alice1->exchangeSecretKey, $bob->exchangePublicKey);
    $shared2 = $ke->computeSharedKey($alice2->exchangeSecretKey, $bob->exchangePublicKey);

    expect($shared1)->not->toBe($shared2);
});
