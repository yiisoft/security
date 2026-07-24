<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypto;

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
     * @param string $context Unique per-encryption context string. Must match during decryption.
     *
     * @throws EncryptionException If encryption fails.
     *
     * @return string Encrypted payload.
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = '',
    ): string;

    /**
     * Decrypts the given data using the secret and context string.
     *
     * @param string $data Encrypted payload to decrypt.
     * @param string $secret Password or raw key (sensitive). Must be the same as used for encryption.
     * @param string $context Context string that was used during encryption.
     *
     * @throws EncryptionException If decryption fails.
     *
     * @return string Decrypted plaintext.
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = '',
    ): string;
}
