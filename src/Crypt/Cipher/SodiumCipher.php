<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Cipher;

use RuntimeException;
use SensitiveParameter;
use Yiisoft\Security\Crypt\AeadCipherInterface;
use Yiisoft\Security\Crypt\EncryptionException;
use function 
    array_key_exists,
    extension_loaded,
    sodium_crypto_aead_aes256gcm_is_available,
    sodium_crypto_aead_aes256gcm_encrypt;

final class SodiumCipher implements AeadCipherInterface
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
        'AES-256-GCM' => [SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES, SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES],
        'ChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES],
        'XChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES],
    ];

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     * @param string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512. @see https://php.net/manual/en/function.hash-algos.php
     */
    public function __construct(
        private readonly string $cipher = 'AES-256-GCM',
    ) {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Encryption requires the Sodium PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException($cipher . ' is not an allowed cipher.');
        }
        if ($cipher === 'AES-256-GCM' && !sodium_crypto_aead_aes256gcm_is_available()) {
            throw new RuntimeException($cipher . ' requires hardware supports hardware-accelerated AES.');
        }
    }

    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nounce,
    ): string
    {
        $encrypted = match ($this->cipher) {
            'AES-256-GCM' => sodium_crypto_aead_aes256gcm_encrypt($data, '', $nounce, $key),
            'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_encrypt($data, '', $nounce, $key),
            'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($data, '', $nounce, $key),
        };

        if ($encrypted === false) {
            throw new EncryptionException('Sodium failure on encryption');
        }

        return $encrypted;
    }

    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nounce,
    ): string
    {
        $decrypted = match ($this->cipher) {
            'AES-256-GCM' => sodium_crypto_aead_aes256gcm_decrypt($data, '', $nounce, $key),
            'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, '', $nounce, $key),
            'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, '', $nounce, $key),
        };

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
