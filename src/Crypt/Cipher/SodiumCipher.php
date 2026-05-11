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
    sodium_crypto_aead_aes256gcm_encrypt,
    sodium_crypto_aead_aes256gcm_decrypt,
    sodium_crypto_aead_chacha20poly1305_ietf_encrypt,
    sodium_crypto_aead_chacha20poly1305_ietf_decrypt,
    sodium_crypto_aead_xchacha20poly1305_ietf_encrypt,
    sodium_crypto_aead_xchacha20poly1305_ietf_decrypt;

/**
 * AEAD cipher implementation using libsodium extension.
 * Supports AES-256-GCM (hardware accelerated), ChaCha20-Poly1305-IETF, and XChaCha20-Poly1305-IETF.
 *
 * @psalm-immutable
 */
final readonly class SodiumCipher implements AeadCipherInterface
{
    /**
     * Authentication tag size in bytes (always 16 for these AEAD modes).
     */
    private const TAG_SIZE = 16;

    /**
     * Look-up table of allowed sodium ciphers with their nonce and key sizes.
     *
     * @var array<string, array{0: int, 1: int}>
     *
     * @psalm-var array<string, array{int, int}>
     */
    private const ALLOWED_CIPHERS = [
        'AES-256-GCM' => [SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES, SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES],
        'ChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES],
        'XChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES],
    ];

    /**
     * @param string $cipher The cipher to use (must be one of ALLOWED_CIPHERS keys).
     *
     * @throws RuntimeException If sodium extension is missing, cipher not allowed, or AES-256-GCM without hardware support.
     */
    public function __construct(
        private string $cipher = 'AES-256-GCM',
    ) {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Encryption requires the Sodium PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException($cipher . ' is not an allowed cipher.');
        }
        if ($cipher === 'AES-256-GCM' && !sodium_crypto_aead_aes256gcm_is_available()) {
            throw new RuntimeException($cipher . ' requires hardware that supports hardware-accelerated AES.');
        }
    }

    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce,
    ): string
    {
        $encrypted = match ($this->cipher) {
            'AES-256-GCM' => sodium_crypto_aead_aes256gcm_encrypt($data, '', $nonce, $key),
            'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_encrypt($data, '', $nonce, $key),
            'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($data, '', $nonce, $key),
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
        string $nonce,
    ): string
    {
        $decrypted = match ($this->cipher) {
            'AES-256-GCM' => sodium_crypto_aead_aes256gcm_decrypt($data, '', $nonce, $key),
            'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, '', $nonce, $key),
            'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, '', $nonce, $key),
        };

        if ($decrypted === false) {
            throw new EncryptionException('Sodium failure on decryption');
        }

        return $decrypted;
    }

    public function getNonceSize(): int
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
