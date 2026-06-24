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

use function hash;
use function hash_hkdf;
use function hash_hmac_algos;
use function in_array;

/**
 * KDF that directly applies HKDF (HMAC-based Key Derivation Function) to the input secret.
 * Suitable for deriving additional keys from a high-entropy secret (random key).
 */
final readonly class KdfKey implements KdfInterface
{
    /**
     * Static salt used in HKDF extraction phase.
     *
     * This salt is **fixed** for all derivations performed by this instance.
     * It serves as a domain separator and provides additional protection against
     * certain attacks when the input secret is not uniformly random.
     *
     * If provided, it must be exactly the length of the hash output.
     */
    private string $hashStaticSalt;

    /**
     * @param string $hashAlgo Hash algorithm for key derivation {@see hash_hmac_algos()}.
     * @param string|Stringable $hashStaticSalt Optional static salt.
     * @param int $saltSize Required size of the dynamic salt in bytes.
     * If set to 0, the salt is disabled. In that case, the `$context` parameter passed to
     * {@see derive()} MUST be random or unique for each derivation.
     *
     * @psalm-param int<0, max> $saltSize
     *
     * @throws RuntimeException
     */
    public function __construct(
        private string $hashAlgo = 'sha256',
        string|Stringable $hashStaticSalt = '',
        private int $saltSize = 32,
    ) {
        if (!in_array($hashAlgo, hash_hmac_algos())) {
            throw new RuntimeException("'{$hashAlgo}' is not an allowed algorithm.");
        }

        $this->hashStaticSalt = (string) $hashStaticSalt;

        if ($this->hashStaticSalt !== ''
            && ($staticSaltSize = StringHelper::byteLength(hash($this->hashAlgo, '', true))) !== StringHelper::byteLength($this->hashStaticSalt)
        ) {
            throw new RuntimeException("Static salt must be {$staticSaltSize} bytes long.");
        }
    }

    /**
     * Derives a key using HKDF (RFC 5869).
     *
     * The HKDF `info` parameter is built as `$context . $salt`. This allows the application to provide
     * a fixed `$context` while using a random `$salt` as a per‑operation unique part of the info.
     * This is useful when the application only supplies a static context
     * but still needs domain separation and randomness in the derivation.
     *
     * @param string $secret High-entropy secret key (must be at least as long as the hash output).
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context (used as prefix of HKDF info).
     * @param string $salt Dynamic salt value. Mmust be exactly {@see getSaltSize()} bytes if salt size > 0,
     * otherwise empty. Acts as a random suffix of the HKDF info. If salt size is 0, ensure
     * the `$context` is random or unique per call.
     *
     * @psalm-mutation-free
     *
     * @throws EncryptionException
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
        if (StringHelper::byteLength($salt) !== $this->saltSize) {
            throw new EncryptionException("Salt must be {$this->saltSize} bytes long.");
        }

        try {
            return hash_hkdf($this->hashAlgo, $secret, $keySize, $context . $salt, $this->hashStaticSalt);
        } catch (ValueError $e) {
            throw new EncryptionException($e->getMessage());
        }
    }

    /**
     * Returns the required dynamic salt size in bytes.
     *
     * @return int Salt size (0 if no salt is used).
     *
     * @psalm-return int<0, max>
     */
    public function getSaltSize(): int
    {
        return $this->saltSize;
    }
}
