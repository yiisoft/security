<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Cipher;

use RuntimeException;
use SensitiveParameter;
use Yiisoft\Security\Crypt\AeadCipherInterface;
use Yiisoft\Security\Crypt\EncryptionException;

final readonly class OpenSSLCipher implements AeadCipherInterface
{
    private const TAG_SIZE = 16;

    /**
     * @var array[] Look-up table of block sizes and key sizes for each supported OpenSSL cipher.
     *
     * In each element, the key is one of the ciphers supported by OpenSSL {@see openssl_get_cipher_methods()}.
     * The value is an array of two integers, the first is the cipher's block size in bytes and the second is
     * the key size in bytes.
     *
     * > Note: Yii's encryption protocol uses the same size for cipher key, HMAC signature key and key
     * derivation salt.
     */
    private const ALLOWED_CIPHERS = [
        'AES-128-GCM' => [12, 16],
        'AES-192-GCM' => [12, 24],
        'AES-256-GCM' => [12, 32],
    ];

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     * @param string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512. @see https://php.net/manual/en/function.hash-algos.php
     */
    public function __construct(
        private string $cipher = 'AES-256-GCM',
    ) {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('Encryption requires the OpenSSL PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException($cipher . ' is not an allowed cipher.');
        }
    }

    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nounce,
    ): string
    {
        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA, $nounce, $tag, '', self::TAG_SIZE);

        if ($encrypted === false) {
            throw new EncryptionException('Sodium failure on encryption');
        }

        return $encrypted . $tag;
    }

    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nounce,
    ): string
    {
        $tag = mb_substr($data, -self::TAG_SIZE, null, '8bit');
        $encrypted = mb_substr($data, 0, -self::TAG_SIZE, '8bit');

        $decrypted = openssl_decrypt($encrypted, $this->cipher, $key, OPENSSL_RAW_DATA, $nounce, $tag);

        if ($decrypted === false) {
            throw new EncryptionException('Sodium failure on decryption');
        }

        return $decrypted;
    }

    public function getNounceSize(): int
    {
        return self::ALLOWED_CIPHERS[$this->cipher][0];
    }

    public function getKeySize(): int
    {
        return self::ALLOWED_CIPHERS[$this->cipher][1];
    }

    public function getTagSize(): int
    {
        return self::TAG_SIZE;
    }
}
