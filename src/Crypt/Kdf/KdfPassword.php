<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Kdf;

use RuntimeException;
use SensitiveParameter;
use ValueError;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\KdfInterface;
use function 
    hash_hkdf,
    hash_pbkdf2;

/**
 * KDF that first applies PBKDF2 to the input password,
 * then applies HKDF to the result. Suitable for deriving cryptographic keys from low-entropy passwords.
 */
final readonly class KdfPassword implements KdfInterface
{
    /**
     * @param string $algorithm Hash algorithm for key derivation.
     * @param int $iterations Derivation iterations count.
     * See [PBKDF2](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) for more details.
     */
    public function __construct(
        private string $algorithm = 'sha256',
        private int $iterations = 600_000,
    ) {
        if (!in_array($algorithm, hash_hmac_algos())) {
            throw new RuntimeException($algorithm . ' is not an allowed algorithm.');
        }

        if ($iterations <= 0) {
            throw new RuntimeException("Iterations must be greather then 0, but {$iterations} provided.");
        }
    }

    /**
     * Derives a key from a password using PBKDF2 + HKDF.
     *
     * Steps:
     * 1. PBKDF2 expands the password and salt into an intermediate key.
     * 2. HKDF derives the final key of requested size using the context as info.
     *
     * @param string $secret The password (low-entropy secret). Sensitive.
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context (used as HKDF info).
     * @param string $salt Salt value (must be random and unique, at least 16 bytes).
     *
     * @return string Derived key (raw binary).
     *
     * @throws RuntimeException If PBKDF2 or HKDF fails.
     * 
     * @psalm-mutation-free
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
            $key = hash_pbkdf2($this->algorithm, $secret, $salt, $this->iterations, $keySize, true);

            return hash_hkdf($this->algorithm, $key, $keySize, $context);
        } catch (ValueError $e) {
            throw new EncryptionException($e->getMessage());
        }
    }
}
