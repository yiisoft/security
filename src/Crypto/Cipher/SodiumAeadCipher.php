<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypto\Cipher;

use RuntimeException;
use SensitiveParameter;
use SodiumException;
use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Security\Crypto\EncryptionException;

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
 * Authentication tag is always 16 bytes and is included in the returned ciphertext.
 */
final readonly class SodiumAeadCipher implements CipherInterface
{
    /**
     * Authentication tag size in bytes (constant for all supported modes).
     */
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
     * Look-up table of allowed Sodium ciphers.
     *
     * Each entry maps a cipher name to:
     * - Key size (bytes) – always 32 for these ciphers.
     * - Nonce size (bytes).
     *
     * @psalm-var array<string, array{32, int}>
     */
    private const ALLOWED_CIPHERS = [
        'AES-256-GCM' => [32, 12],
        'CHACHA20-POLY1305-IETF' => [32, 12],
        'XCHACHA20-POLY1305-IETF' => [32, 24],
    ];

    /**
     * @param string $cipher The cipher to use (must be one of ALLOWED_CIPHERS keys).
     *
     * @throws RuntimeException If sodium extension is missing, cipher not allowed, or AES-256-GCM without hardware support.
     */
    public function __construct(
        private string $cipher = 'CHACHA20-POLY1305-IETF',
    ) {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Encryption requires the Sodium PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException("'{$cipher}' is not an allowed cipher.");
        }
        if ($cipher === 'AES-256-GCM' && !sodium_crypto_aead_aes256gcm_is_available()) {
            throw new RuntimeException("'{$cipher}' requires hardware that supports hardware-accelerated AES.");
        }

        [$this->keySize, $this->nonceSize] = self::ALLOWED_CIPHERS[$this->cipher];
    }

    /**
     * {@inheritdoc}
     *
     * The key and nonce must match the required sizes for the selected cipher.
     *
     * @throws EncryptionException If encryption fails (e.g., invalid key/nonce length or Sodium error).
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce = '',
        string $aad = '',
    ): string {
        try {
            $encrypted = match ($this->cipher) {
                'AES-256-GCM' => sodium_crypto_aead_aes256gcm_encrypt($data, $aad, $nonce, $key),
                'CHACHA20-POLY1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_encrypt($data, $aad, $nonce, $key),
                'XCHACHA20-POLY1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($data, $aad, $nonce, $key),
            };
        } catch (SodiumException $e) {
            throw new EncryptionException($e->getMessage());
        }

        return $encrypted;
    }

    /**
     * {@inheritdoc}
     *
     * The key and nonce must match the values used during encryption.
     *
     * @throws EncryptionException If decryption fails (e.g., invalid key/nonce, tag mismatch, or Sodium error).
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce = '',
        string $aad = '',
    ): string {
        try {
            $decrypted = match ($this->cipher) {
                'AES-256-GCM' => sodium_crypto_aead_aes256gcm_decrypt($data, $aad, $nonce, $key),
                'CHACHA20-POLY1305-IETF' => sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, $aad, $nonce, $key),
                'XCHACHA20-POLY1305-IETF' => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($data, $aad, $nonce, $key),
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
