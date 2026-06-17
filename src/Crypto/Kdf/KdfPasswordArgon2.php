<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypto\Kdf;

use RuntimeException;
use SensitiveParameter;
use SodiumException;
use Stringable;
use ValueError;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\KdfInterface;

use function extension_loaded;
use function sodium_crypto_pwhash;

/**
 * KDF that applies Argon2 to the input password, followed by HKDF for key expansion.
 * Suitable for deriving high-entropy cryptographic keys from low-entropy passwords.
 *
 * Note: `sodium_crypto_pwhash()` always uses a single thread (p=1).
 */
final class KdfPasswordArgon2 implements KdfInterface
{
    private const PW_HASH_LENGTH = 32;
    private const PW_SALT_SIZE = 16;

    private readonly KdfKey $kdfKey;

    /**
     * @param int $algo Argon2 variant (defaults to Argon2id, constant value 2 – `SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13`).
     * @param int $opslimit Number of CPU iterations (time cost). Default is 2 (`SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE`).
     * @param int $memlimit RAM limit in bytes (memory cost). Default is 67108864 (`SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE`).
     * @param string $hashAlgo Hash algorithm for the HKDF expansion step. Must be one of {@see hash_hmac_algos()}.
     * @param string|Stringable $hashStaticSalt Optional static salt for the HKDF step {@see KdfKey::$hashStaticSalt}.
     *
     * @throws RuntimeException If the Sodium extension is missing.
     *
     * @see https://owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2
     */
    public function __construct(
        private readonly int $algo = 2,
        private readonly int $opslimit = 2,
        private readonly int $memlimit = 67108864,
        string $hashAlgo = 'sha256',
        string|Stringable $hashStaticSalt = '',
    ) {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('Encryption requires the Sodium PHP extension.');
        }

        $this->kdfKey = new KdfKey(
            hashAlgo: $hashAlgo,
            hashStaticSalt: $hashStaticSalt,
            saltSize: 0,
        );
    }

    /**
     * Derives a key from a password using Argon2 + HKDF.
     *
     * Steps:
     * 1. Argon2id hashes the password and salt into a high-entropy intermediate key (32 bytes).
     * 2. HKDF expands the intermediate key to the requested size using the context as info.
     *
     * @param string $secret The password (low-entropy secret). Sensitive.
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context (used as HKDF info).
     * @param string $salt Salt value for Argon2 (must be random and unique, exactly {@see getSaltSize()} bytes).
     *
     * @throws EncryptionException If hashing or key expansion fails.
     *
     * @psalm-mutation-free
     *
     * @return string Derived key (raw binary).
     */
    public function derive(
        #[SensitiveParameter]
        string $secret,
        int $keySize,
        string $context,
        string $salt = '',
    ): string {
        try {
            $key = sodium_crypto_pwhash(self::PW_HASH_LENGTH, $secret, $salt, $this->opslimit, $this->memlimit, $this->algo);

            return $this->kdfKey->derive($key, $keySize, $context);
        } catch (ValueError|SodiumException $e) {
            throw new EncryptionException($e->getMessage());
        }
    }

    /**
     * Returns the salt size required by Argon2.
     *
     * @return int Fixed salt size.
     *
     * @psalm-return 16
     */
    public function getSaltSize(): int
    {
        return self::PW_SALT_SIZE;
    }
}
