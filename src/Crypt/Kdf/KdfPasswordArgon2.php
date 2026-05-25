<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Kdf;

use RuntimeException;
use SensitiveParameter;
use SodiumException;
use ValueError;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\KdfInterface;

use function extension_loaded;
use function hash_hkdf;
use function hash_hmac_algos;
use function in_array;
use function sodium_crypto_pwhash;

/**
 * KDF that applies Argon2id to the input password, followed by HKDF for key expansion.
 * Suitable for deriving high-entropy cryptographic keys from low-entropy passwords.
 *
 * Note: `sodium_crypto_pwhash()` always uses a single thread (p=1).
 */
final class KdfPasswordArgon2 implements KdfInterface
{
    /**
     * @param string $hashAlgo Hash algorithm for the HKDF expansion step. {@see hash_hmac_algos()}
     * @param int $algo Argon2 variant (defaults to Argon2id).
     * @param int $opslimit Number of CPU iterations (time cost).
     * @param int $memlimit RAM limit in bytes (memory cost).
     * See [Argon2 recommendations](https://owasp.org) for details.
     *
     * @psalm-param int<1, max> $saltSize
     *
     * @throws RuntimeException If the Sodium extension is missing.
     */
    public function __construct(
        private readonly string $hashAlgo = 'sha256',
        private readonly int $algo = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        private readonly int $opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        private readonly int $memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    ) {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Encryption requires the Sodium PHP extension.');
        }
        if (!in_array($hashAlgo, hash_hmac_algos())) {
            throw new RuntimeException($hashAlgo . ' is not an allowed algorithm.');
        }
    }

    /**
     * Derives a key from a password using Argon2 + HKDF.
     *
     * Steps:
     * 1. Argon2id hashes the password and salt into a high-entropy intermediate key.
     * 2. HKDF expands the result to the requested size using the context as info.
     *
     * @param string $secret The password (low-entropy secret). Sensitive.
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context (used as HKDF info).
     * @param string $salt Salt value (must be random and unique, 16 bytes for Argon2).
     *
     * @throws EncryptionException If hashing or key expansion fails.
     * @return string Derived key (raw binary).
     *
     * @psalm-mutation-free
     */
    public function createKey(
        #[SensitiveParameter]
        string $secret,
        int $keySize,
        string $context,
        string $salt,
    ): string {
        try {
            $key = sodium_crypto_pwhash($keySize, $secret, $salt, $this->opslimit, $this->memlimit, $this->algo);

            return hash_hkdf($this->hashAlgo, $key, $keySize, $context);
        } catch (ValueError|SodiumException $e) {
            throw new EncryptionException($e->getMessage());
        }
    }

    public function getSaltSize(): int
    {
        return SODIUM_CRYPTO_PWHASH_SALTBYTES;
    }
}
