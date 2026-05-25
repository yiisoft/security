<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Cipher;

use RuntimeException;
use SensitiveParameter;
use SodiumException;
use Yiisoft\Security\Crypt\AeadCipherInterface;
use Yiisoft\Security\Crypt\EncryptionException;

use function array_key_exists;
use function extension_loaded;
use function sodium_crypto_aead_aes256gcm_is_available;
use function sodium_crypto_aead_aes256gcm_encrypt;
use function sodium_crypto_aead_aes256gcm_decrypt;
use function sodium_crypto_aead_chacha20poly1305_ietf_encrypt;
use function sodium_crypto_aead_chacha20poly1305_ietf_decrypt;
use function sodium_crypto_aead_xchacha20poly1305_ietf_encrypt;
use function sodium_crypto_aead_xchacha20poly1305_ietf_decrypt;

/**
 * AEAD cipher implementation using libsodium extension.
 * Supports AES-256-GCM (hardware accelerated), ChaCha20-Poly1305-IETF, and XChaCha20-Poly1305-IETF.
 */
final class SodiumAeadCipher implements AeadCipherInterface
{
    /**
     * Authentication tag size in bytes (always 16 for these AEAD modes).
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
     * Look-up table of allowed Sodium ciphers.
     *
     * Each entry maps a cipher name to:
     * - Key size (bytes)   – required key length.
     * - Nonce size (bytes) – used as nonce length.
     *
     * @var array<string, array{0: int, 1: int}>
     *
     * @psalm-var array<string, array{int, int}>
     */
    private const ALLOWED_CIPHERS = [
        'AES-256-GCM' => [SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES],
        'ChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES],
        'XChaCha20-Poly1305-IETF' => [SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES],
    ];

    /**
     * @param string $cipher The cipher to use (must be one of ALLOWED_CIPHERS keys).
     *
     * @throws RuntimeException If sodium extension is missing, cipher not allowed, or AES-256-GCM without hardware support.
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
            throw new RuntimeException($cipher . ' requires hardware that supports hardware-accelerated AES.');
        }

        [$this->keySize, $this->nonceSize] = self::ALLOWED_CIPHERS[$this->cipher];
    }

    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce,
    ): string {
        try {
            $encrypted = match ($this->cipher) {
                'AES-256-GCM' => sodium_crypto_aead_aes256gcm_encrypt($data, '', $nonce, $key),
                'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_encrypt($data, '', $nonce, $key),
                'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($data, '', $nonce, $key),
            };
        } catch (SodiumException $e) {
            throw new EncryptionException($e->getMessage());
        }

        return $encrypted;
    }

    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce,
    ): string {
        try {
            $decrypted = match ($this->cipher) {
                'AES-256-GCM' => sodium_crypto_aead_aes256gcm_decrypt($data, '', $nonce, $key),
                'ChaCha20-Poly1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, '', $nonce, $key),
                'XChaCha20-Poly1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, '', $nonce, $key),
            };
        } catch (SodiumException $e) {
            throw new EncryptionException($e->getMessage());
        }

        if ($decrypted === false) {
            throw new EncryptionException('Sodium failure on decryption');
        }

        return $decrypted;
    }

    public function getKeySize(): int
    {
        return $this->keySize;
    }

    public function getNonceSize(): int
    {
        return $this->nonceSize;
    }

    public function getTagSize(): int
    {
        return self::TAG_SIZE;
    }
}
