<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;

/**
 * Interface for key derivation functions (KDF).
 * Used to derive cryptographic keys from a secret (password or raw key material).
 */
interface KdfInterface
{
    /**
     * Derives a key of the specified size from the given secret.
     *
     * @param string $secret The input secret (password or raw key material). Sensitive parameter.
     * @param int $keySize Desired key length in bytes.
     * @param string $context Application-specific context string (used as HKDF info).
     * @param string $salt Salt value (must be random and unique for each derivation).
     *
     * @throws \RuntimeException If key derivation fails.
     * @return string The derived key (raw binary string).
     */
    public function createKey(
        #[SensitiveParameter]
        string $secret,
        int $keySize,
        string $context,
        string $salt,
    ): string;

    /**
     * @return int Salt size in bytes.
     *
     * @psalm-return int<1, max>
     */
    public function getSaltSize(): int;
}
