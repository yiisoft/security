<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Cipher;

use RuntimeException;
use SensitiveParameter;
use Yiisoft\Security\Crypt\AeadCipherInterface;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Strings\StringHelper;

use function array_key_exists;
use function extension_loaded;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_error_string;

/**
 * AEAD cipher implementation using OpenSSL extension.
 * Supports only AES-GCM family (128, 192, 256) with 16-byte authentication tags.
 */
final class OpenSSLAeadCipher implements AeadCipherInterface
{
    /**
     * Authentication tag size in bytes (always 16 for GCM).
     */
    private const TAG_SIZE = 16;

    /**
     * @psalm-var int<1, max>
     */
    private readonly int $keySize;

    /**
     * @psalm-var int<1, max>
     */
    private readonly int $nonceSize;

    /**
     * Look-up table of allowed OpenSSL ciphers.
     *
     * Each entry maps a cipher name to:
     * - Key size (bytes)   – required key length.
     * - Nonce size (bytes) – used as IV length.
     *
     * @var array<string, array{0: int, 1: int}>
     *
     * @psalm-var array<string, array{int, int}>
     */
    private const ALLOWED_CIPHERS = [
        'AES-128-GCM' => [16, 12],
        'AES-192-GCM' => [24, 12],
        'AES-256-GCM' => [32, 12],
    ];

    /**
     * @param string $cipher Cipher method (must be one of ALLOWED_CIPHERS keys).
     *
     * @throws RuntimeException If OpenSSL extension is not loaded or the cipher is not allowed.
     */
    public function __construct(
        private readonly string $cipher = 'AES-256-GCM',
    ) {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('Encryption requires the OpenSSL PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException($cipher . ' is not an allowed cipher.');
        }

        [$this->keySize, $this->nonceSize] = self::ALLOWED_CIPHERS[$this->cipher];
    }

    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce,
    ): string {
        if (StringHelper::byteLength($key) !== $this->keySize) {
            throw new EncryptionException("Key must be {$this->keySize} bytes long.");
        }
        if (StringHelper::byteLength($nonce) !== $this->nonceSize) {
            throw new EncryptionException("Nonce must be {$this->nonceSize} bytes long.");
        }

        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA | OPENSSL_DONT_ZERO_PAD_KEY, $nonce, $tag, '', self::TAG_SIZE);

        if ($encrypted === false) {
            $error = openssl_error_string() ?: 'Unknown error';
            throw new EncryptionException('OpenSSL failure on encryption: ' . $error);
        }

        return $encrypted . $tag;
    }

    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce,
    ): string {
        if (StringHelper::byteLength($key) !== $this->keySize) {
            throw new EncryptionException("Key must be {$this->keySize} bytes long.");
        }
        if (StringHelper::byteLength($nonce) !== $this->nonceSize) {
            throw new EncryptionException("Nonce must be {$this->nonceSize} bytes long.");
        }

        $tag = StringHelper::byteSubstring($data, -self::TAG_SIZE);
        $ciphertext = StringHelper::byteSubstring($data, 0, -self::TAG_SIZE);

        $decrypted = openssl_decrypt($ciphertext, $this->cipher, $key, OPENSSL_RAW_DATA | OPENSSL_DONT_ZERO_PAD_KEY, $nonce, $tag);

        if ($decrypted === false) {
            $error = openssl_error_string() ?: 'Unknown error';
            throw new EncryptionException('OpenSSL failure on decryption: ' . $error);
        }

        return $decrypted;
    }

    public function getKeySize(): int
    {
        return $this->keySize;
    }

    /**
     * @psalm-return int<1, max>
     */
    public function getNonceSize(): int
    {
        return $this->nonceSize;
    }

    public function getTagSize(): int
    {
        return self::TAG_SIZE;
    }
}
