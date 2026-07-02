<?php

declare(strict_types=1);

use Wenbo\ReqResCrypto\Core\Encrypter;
use Wenbo\ReqResCrypto\Core\Exceptions\CryptoException;

beforeEach(function () {
    $this->key = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
    $this->encrypter = new Encrypter($this->key);
});

// 基础加密
test('encrypt returns nonce + ciphertext and decrypt restores', function () {
    $plaintext = 'PHP request-response crypto test';

    $cipher = $this->encrypter->encrypt($plaintext);

    $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    expect(strlen($cipher))->toBeGreaterThanOrEqual($nonceLen + 1);

    $decrypted = $this->encrypter->decrypt($cipher);
    expect($decrypted)->toBe($plaintext);
});

// 二进制数据
test('encrypt and decrypt binary payload', function () {
    $plaintext = random_bytes(1024);

    $cipher = $this->encrypter->encrypt($plaintext);
    $decrypted = $this->encrypter->decrypt($cipher);

    expect($decrypted)->toBe($plaintext);
});

// 加密非确定性
test('two encryptions of same data differ', function () {
    $c1 = $this->encrypter->encrypt('same');
    $c2 = $this->encrypter->encrypt('same');

    expect($c1)->not->toBe($c2); // nonce 随机
});

// 对抗式：空密钥拒绝
test('constructor rejects empty key', function () {
    expect(fn () => new Encrypter(''))
        ->toThrow(CryptoException::class);
});

// 对抗式：不同密钥解密失败
test('decrypt fails with wrong key', function () {
    $another = new Encrypter(sodium_crypto_aead_xchacha20poly1305_ietf_keygen());

    $cipher = $this->encrypter->encrypt('secret');

    expect(fn () => $another->decrypt($cipher))
        ->toThrow(CryptoException::class);
});

// 对抗式：截断密文
test('decrypt fails on truncated ciphertext', function () {
    $cipher = $this->encrypter->encrypt('hello');
    $truncated = mb_substr($cipher, 0, 25, '8bit'); // 不足 nonce + 1 密文字节

    expect(fn () => $this->encrypter->decrypt($truncated))
        ->toThrow(CryptoException::class);
});

// 对抗式：篡改密文
test('decrypt fails on tampered ciphertext', function () {
    $cipher = $this->encrypter->encrypt('hello');
    $offset = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    $cipher[$offset] = chr(ord($cipher[$offset]) ^ 0xFF);

    expect(fn () => $this->encrypter->decrypt($cipher))
        ->toThrow(CryptoException::class);
});

// 超大输入（1MB）
test('encrypt and decrypt large payload', function () {
    $plaintext = str_repeat('A', 1_048_576);

    $cipher = $this->encrypter->encrypt($plaintext);
    $decrypted = $this->encrypter->decrypt($cipher);

    expect($decrypted)->toBe($plaintext);
});
