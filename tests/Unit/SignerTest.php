<?php

declare(strict_types=1);

use Wenbo\ReqResCrypto\Core\KeyPair;
use Wenbo\ReqResCrypto\Core\Signer;
use Wenbo\ReqResCrypto\Core\Exceptions\SignatureException;

// 基础签名验签
test('sign produces valid Ed25519 signature', function () {
    $pair = KeyPair::generate();
    $signer = new Signer($pair->signSecretKey, $pair->signPublicKey);

    $sig = $signer->sign('hello');

    expect($sig)->not->toBeEmpty();

    // 功能验证：签名能被验签
    $signer->verify('hello', $sig);
    expect(true)->toBeTrue();
});

// 验签通过
test('verify passes for valid signature', function () {
    $pair = KeyPair::generate();
    $signer = new Signer($pair->signSecretKey, $pair->signPublicKey);
    $message = 'the quick brown fox';

    $sig = $signer->sign($message);

    // 不抛出异常即通过
    $signer->verify($message, $sig);
    expect(true)->toBeTrue();
});

// 对抗式审查：伪造签名
test('verify throws on tampered message', function () {
    $pair = KeyPair::generate();
    $signer = new Signer($pair->signSecretKey, $pair->signPublicKey);

    $sig = $signer->sign('original');

    expect(fn () => $signer->verify('tampered', $sig))
        ->toThrow(SignatureException::class);
});

// 对抗式审查：伪造签名字节
test('verify throws on forged signature bytes', function () {
    $pair = KeyPair::generate();
    $signer = new Signer($pair->signSecretKey, $pair->signPublicKey);
    $message = 'msg';

    $sig = $signer->sign($message);
    // 翻转签名第一个字节
    $sig[0] = chr(ord($sig[0]) ^ 0xFF);

    expect(fn () => $signer->verify($message, $sig))
        ->toThrow(SignatureException::class);
});

// 对抗式审查：空消息
test('sign and verify empty string', function () {
    $pair = KeyPair::generate();
    $signer = new Signer($pair->signSecretKey, $pair->signPublicKey);

    $sig = $signer->sign('');
    $signer->verify('', $sig);

    expect(true)->toBeTrue();
});

// 对抗式审查：空私钥仍可构造（仅验签场景），但签名会拒绝
test('sign rejects empty secret key', function () {
    $pair = KeyPair::generate();
    $signer = new Signer('', $pair->signPublicKey);

    expect(fn () => $signer->sign('msg'))
        ->toThrow(SignatureException::class);
});

test('constructor rejects empty public key', function () {
    expect(fn () => new Signer('aa', ''))
        ->toThrow(SignatureException::class);
});
