<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypto\Cipher;

use RuntimeException;
use SensitiveParameter;
use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Strings\StringHelper;

use function array_key_exists;
use function extension_loaded;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_error_string;

use const OPENSSL_DONT_ZERO_PAD_KEY;
use const OPENSSL_RAW_DATA;

/**
 * AEAD cipher implementation using OpenSSL extension.
 * Supports AES-GCM (128, 192, 256) and ChaCha20-Poly1305(IETF variant) with 16-byte authentication tags.
 */
final readonly class OpenSSLAeadCipher implements CipherInterface
{
    private const TAG_SIZE = 16;

    /**
     * @psalm-var int<1, max>
     */
    private int $keySize;

    /**
     * @psalm-var int<1, max>
     */
    private int $nonceSize;

    /**
     * Look-up table of allowed OpenSSL ciphers.
     *
     * Each entry maps a cipher name to:
     * - Key size (bytes)
     * - Nonce size (bytes)
     *
     * @psalm-var array<string, array{int, int}>
     */
    private const ALLOWED_CIPHERS = [
        'AES-128-GCM' => [16, 12],
        'AES-192-GCM' => [24, 12],
        'AES-256-GCM' => [32, 12],
        'CHACHA20-POLY1305' => [32, 12], // IETF variant
    ];

    /**
     * @param string $cipher Cipher method (must be one of ALLOWED_CIPHERS keys).
     *
     * @throws RuntimeException If OpenSSL extension is not loaded or the cipher is not allowed.
     */
    public function __construct(
        private string $cipher = 'CHACHA20-POLY1305',
    ) {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('Encryption requires the OpenSSL PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException("'{$cipher}' is not an allowed cipher.");
        }

        [$this->keySize, $this->nonceSize] = self::ALLOWED_CIPHERS[$this->cipher];
    }

    /**
     * {@inheritdoc}
     *
     * @throws EncryptionException If key or nonce length is invalid, or OpenSSL encryption fails.
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce = '',
        string $aad = '',
    ): string {
        if (StringHelper::byteLength($key) !== $this->keySize) {
            throw new EncryptionException("Key must be {$this->keySize} bytes long.");
        }
        if (StringHelper::byteLength($nonce) !== $this->nonceSize) {
            throw new EncryptionException("Nonce must be {$this->nonceSize} bytes long.");
        }

        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA | OPENSSL_DONT_ZERO_PAD_KEY, $nonce, $tag, $aad, self::TAG_SIZE);

        if ($encrypted === false) {
            $error = openssl_error_string() ?: 'Unknown error';
            throw new EncryptionException('OpenSSL failure on encryption: ' . $error);
        }

        return $encrypted . $tag;
    }

    /**
     * {@inheritdoc}
     *
     * @throws EncryptionException If key or nonce length is invalid, or OpenSSL decryption fails (including tag mismatch).
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce = '',
        string $aad = '',
    ): string {
        if (StringHelper::byteLength($key) !== $this->keySize) {
            throw new EncryptionException("Key must be {$this->keySize} bytes long.");
        }
        if (StringHelper::byteLength($nonce) !== $this->nonceSize) {
            throw new EncryptionException("Nonce must be {$this->nonceSize} bytes long.");
        }

        $tag = StringHelper::byteSubstring($data, -self::TAG_SIZE);
        $ciphertext = StringHelper::byteSubstring($data, 0, -self::TAG_SIZE);

        $decrypted = openssl_decrypt($ciphertext, $this->cipher, $key, OPENSSL_RAW_DATA | OPENSSL_DONT_ZERO_PAD_KEY, $nonce, $tag, $aad);

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
     * {@inheritdoc}
     *
     * @psalm-return int<1, max>
     */
    public function getNonceSize(): int
    {
        return $this->nonceSize;
    }

    /**
     * {@inheritdoc}
     *
     * @psalm-return 16
     */
    public function getOverheadSize(): int
    {
        return self::TAG_SIZE;
    }
}
