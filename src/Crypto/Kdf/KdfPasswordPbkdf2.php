<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypto\Kdf;

use RuntimeException;
use SensitiveParameter;
use Stringable;
use ValueError;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Strings\StringHelper;

use function hash_pbkdf2;
use function sprintf;

/**
 * KDF that first applies PBKDF2 to the input password,
 * then applies HKDF to the result. Suitable for deriving cryptographic keys from low-entropy passwords.
 */
final readonly class KdfPasswordPbkdf2 implements KdfInterface
{
    private const PW_HASH_ALGO = 'sha256';
    private const PW_SALT_SIZE = 32;

    private KdfKey $kdfKey;

    /**
     * @param int $iterations Derivation iteration count (must be > 0). See OWASP recommendations.
     * @param string $hashAlgo Hash algorithm for the HKDF expansion step. Must be one of {@see hash_hmac_algos()}.
     * @param string|Stringable $hashStaticSalt Optional static salt for the HKDF step {@see KdfKey::$hashStaticSalt}.
     *
     * @throws RuntimeException If iteration count is invalid or the inner KDF construction fails.
     *
     * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
     */
    public function __construct(
        private int $iterations = 600_000,
        string $hashAlgo = 'sha256',
        string|Stringable $hashStaticSalt = '',
    ) {
        if ($iterations <= 0) {
            throw new RuntimeException("Iterations must be greater than 0, but {$iterations} provided.");
        }

        $this->kdfKey = new KdfKey(
            hashAlgo: $hashAlgo,
            hashStaticSalt: $hashStaticSalt,
            saltSize: 0,
        );
    }

    /**
     * Derives a key from a password using PBKDF2 + HKDF.
     *
     * Steps:
     * 1. PBKDF2 expands the password and salt into an intermediate key (using SHA-256, raw output).
     * 2. HKDF derives the final key of requested size using the context as info.
     *
     * @param string $secret The password (low-entropy secret). Sensitive.
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context (used as HKDF info).
     * @param string $salt Salt value (must be random and unique, exactly {@see getSaltSize()} bytes).
     *
     * @throws EncryptionException If PBKDF2 or HKDF fails, or if salt length is invalid.
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
        /** @psalm-suppress ImpureMethodCall */
        if (StringHelper::byteLength($salt) !== self::PW_SALT_SIZE) {
            throw new EncryptionException(sprintf('Salt must be %d bytes long.', self::PW_SALT_SIZE));
        }

        try {
            $key = hash_pbkdf2(self::PW_HASH_ALGO, $secret, $salt, $this->iterations, 0, true);

            return $this->kdfKey->derive($key, $keySize, $context);
        } catch (ValueError $e) {
            throw new EncryptionException($e->getMessage());
        }
    }

    /**
     * Returns the required salt size in bytes.
     *
     * @return int Fixed salt size.
     *
     * @psalm-return 32
     */
    public function getSaltSize(): int
    {
        return self::PW_SALT_SIZE;
    }
}
