<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;

/**
 * Interface for high-level encryption/decryption with key derivation.
 */
interface CryptorInterface
{
    /**
     * Encrypts the given data using the secret and context string.
     *
     * @param string $data Plaintext to encrypt.
     * @param string $secret Password or raw key (sensitive).
     * @param string $context Application-specific context (used in key derivation).
     *
     * @throws EncryptionException If encryption fails.
     * @throws \RuntimeException If required PHP extension is missing.
     * @return string Encrypted payload (includes nonce, salt, authentication tag, etc.).
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string;

    /**
     * Decrypts the given data using the secret and context string.
     *
     * @param string $data Encrypted payload to decrypt.
     * @param string $secret Password or raw key (sensitive).
     * @param string $context Application-specific context (must match the one used for encryption).
     *
     * @throws EncryptionException If decryption fails.
     * @throws \RuntimeException If required PHP extension is missing or data is malformed.
     * @return string Decrypted plaintext.
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string;
}
