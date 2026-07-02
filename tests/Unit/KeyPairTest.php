<?php

declare(strict_types=1);

use Wenbo\ReqResCrypto\Core\KeyPair;
use Wenbo\ReqResCrypto\Core\Signer;
use Wenbo\ReqResCrypto\Core\Exceptions\KeyException;

// 生成
test('generate produces valid key pair', function () {
    $pair = KeyPair::generate();

    expect($pair->signPublicKey)->not->toBeEmpty();
    expect($pair->signSecretKey)->not->toBeEmpty();
    expect($pair->exchangePublicKey)->not->toBeEmpty();
    expect($pair->exchangeSecretKey)->not->toBeEmpty();
});

// 密钥可用于签名验签（功能验证比字节长度重要的多）
test('generated keys can sign and verify', function () {
    $pair = KeyPair::generate();
    $signer = new Signer($pair->signSecretKey, $pair->signPublicKey);

    $sig = $signer->sign('functional test');
    $signer->verify('functional test', $sig);

    expect(true)->toBeTrue(); // 不抛异常
});

// 可恢复
test('fromStrings restores key pair', function () {
    $original = KeyPair::generate();

    $restored = KeyPair::fromStrings(
        $original->signPublicKey,
        $original->signSecretKey,
        $original->exchangePublicKey,
        $original->exchangeSecretKey,
    );

    expect($restored->signPublicKey)->toBe($original->signPublicKey);
    expect($restored->signSecretKey)->toBe($original->signSecretKey);
    expect($restored->exchangePublicKey)->toBe($original->exchangePublicKey);
    expect($restored->exchangeSecretKey)->toBe($original->exchangeSecretKey);
});

// keyId 一致性与格式
test('keyId is 8 hex chars and deterministic', function () {
    $pair = KeyPair::generate();

    $id = $pair->keyId();

    expect($id)->toMatch('/^[0-9a-f]{8}$/');
    expect($pair->keyId())->toBe($id); // 幂等
});

// 签名公钥的前 4 字节即 KeyId
test('keyId matches first 4 bytes of sign public key', function () {
    $pair = KeyPair::generate();

    expect($pair->keyId())->toBe(bin2hex(mb_substr($pair->signPublicKey, 0, 4, '8bit')));
});

// 对抗式审查：每个 generate 唯一
test('each generate produces unique keys', function () {
    $a = KeyPair::generate();
    $b = KeyPair::generate();

    expect($a->signPublicKey)->not->toBe($b->signPublicKey);
    expect($a->exchangePublicKey)->not->toBe($b->exchangePublicKey);
});
