<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Kdf;

use RuntimeException;
use SensitiveParameter;
use ValueError;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\KdfInterface;
use function 
    hash_hkdf;

/**
 * KDF that directly applies HKDF (HMAC-based Key Derivation Function) to the input secret.
 * Suitable for deriving additional keys from a high-entropy secret (e.g., another key).
 *
 * @psalm-immutable
 */
final readonly class KdfKey implements KdfInterface
{
    public function __construct(
        private string $algorithm = 'sha256',
    ) {
        if (!in_array($algorithm, hash_hmac_algos())) {
            throw new RuntimeException($algorithm . ' is not an allowed algorithm.');
        }
    }

    /**
     * Derives a key using HKDF (RFC 5869).
     *
     * @param string $secret High-entropy secret key (must be at least as long as the hash output).
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context (used as HKDF info).
     * @param string $salt Salt value (optional, but recommended for stronger extraction).
     *
     * @return string Derived key (raw binary).
     *
     * @throws RuntimeException If HKDF fails.
     */
    public function createKey(
        #[SensitiveParameter]
        string $secret,
        int $keySize,
        string $context,
        string $salt,
    ): string
    {
        try {
            return hash_hkdf($this->algorithm, $secret, $keySize, $context, $salt);
        } catch (ValueError $e) {
            throw new EncryptionException($e->getMessage());
        }
    }
}
