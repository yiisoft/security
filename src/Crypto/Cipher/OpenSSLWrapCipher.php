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
use function str_repeat;

use const OPENSSL_DONT_ZERO_PAD_KEY;
use const OPENSSL_RAW_DATA;

/**
 * Key wrapping cipher using OpenSSL (RFC 5649 / AES-KW).
 * Nonce and AAD are ignored.
 *
 * For key wrapping only, not general-purpose encryption.
 * Plaintext and ciphertext MUST be multiples of 8 bytes.
 */
final readonly class OpenSSLWrapCipher implements CipherInterface
{
    /**
     * Tag size in bytes (8 bytes for AES-KW).
     */
    private const TAG_SIZE = 8;

    /**
     * @psalm-var int<1, max>
     */
    private int $keySize;

    /**
     * Dummy nonce (all zeros) to prevent OpenSSL from issuing warnings.
     *
     * The `openssl_encrypt()` and `openssl_decrypt()` functions require an IV parameter,
     * even for key wrap algorithms that don't use one internally. Passing an empty string
     * would trigger a warning. This dummy nonce of the appropriate size satisfies the
     * function signature without affecting the key wrap operation, as the algorithm ignores it.
     */
    private string $dummyNonce;

    /**
     * Look-up table of allowed OpenSSL key wrap ciphers.
     *
     * Each entry maps a cipher name to:
     * - Key size (bytes)
     * - Nonce size (bytes) – though not used, required for interface compatibility.
     *
     * @psalm-var array<string, array{int, int}>
     */
    private const ALLOWED_CIPHERS = [
        'AES-128-WRAP' => [16, 8],
        'AES-192-WRAP' => [24, 8],
        'AES-256-WRAP' => [32, 8],
    ];

    /**
     * @param string $cipher Cipher method (must be one of ALLOWED_CIPHERS keys).
     *
     * @throws RuntimeException If OpenSSL extension is not loaded or the cipher is not allowed.
     */
    public function __construct(
        private string $cipher = 'AES-256-WRAP',
    ) {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('Encryption requires the OpenSSL PHP extension.');
        }
        if (!array_key_exists($cipher, self::ALLOWED_CIPHERS)) {
            throw new RuntimeException("'{$cipher}' is not an allowed cipher.");
        }

        [$this->keySize, $nonceSize] = self::ALLOWED_CIPHERS[$this->cipher];
        $this->dummyNonce = str_repeat("\0", $nonceSize);
    }

    /**
     * {@inheritdoc}
     *
     * Data must be a multiple of 8 bytes.
     * Key wrap does not use a nonce or AAD; both parameters are ignored.
     *
     * @throws EncryptionException If key length is invalid or OpenSSL encryption fails.
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

        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA | OPENSSL_DONT_ZERO_PAD_KEY, $this->dummyNonce);

        if ($encrypted === false) {
            /** @psalm-suppress RiskyTruthyFalsyComparison */
            $error = openssl_error_string() ?: 'Unknown error';
            throw new EncryptionException('OpenSSL failure on encryption: ' . $error);
        }

        return $encrypted;
    }

    /**
     * {@inheritdoc}
     *
     * Data must be a multiple of 8 bytes.
     * Key wrap does not use a nonce or AAD; both parameters are ignored.
     *
     * @throws EncryptionException If key length is invalid or OpenSSL decryption fails.
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

        $decrypted = openssl_decrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA | OPENSSL_DONT_ZERO_PAD_KEY, $this->dummyNonce);

        if ($decrypted === false) {
            /** @psalm-suppress RiskyTruthyFalsyComparison */
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
     * Key wrap does not use a nonce, so this method returns 0.
     *
     * @psalm-return 0
     */
    public function getNonceSize(): int
    {
        return 0;
    }

    /**
     * {@inheritdoc}
     *
     * @psalm-return 8
     */
    public function getOverheadSize(): int
    {
        return self::TAG_SIZE;
    }
}
