<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;

/**
 * Base interface for symmetric encryption ciphers.
 */
interface CipherInterface
{
    /**
     * Encrypts the provided data with the given key and nonce.
     *
     * @param string $data Plaintext to encrypt.
     * @param string $key Secret encryption key (sensitive).
     * @param string $nonce Initialization vector or nonce.
     *
     * @throws EncryptionException If encryption fails.
     * @return string Ciphertext.
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce,
    ): string;

    /**
     * Decrypts the provided ciphertext with the given key and nonce.
     *
     * @param string $data Ciphertext to decrypt.
     * @param string $key Secret encryption key (sensitive).
     * @param string $nonce Nonce used during encryption.
     *
     * @throws EncryptionException If decryption fails.
     * @return string Decrypted plaintext.
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce,
    ): string;

    /**
     * @return int Key size in bytes.
     *
     * @psalm-return int<1, max>
     */
    public function getKeySize(): int;

    /**
     * @return int Nonce size in bytes
     *
     * @psalm-return int<1, max>
     */
    public function getNonceSize(): int;
}
