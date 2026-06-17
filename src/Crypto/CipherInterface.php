<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypto;

use SensitiveParameter;

/**
 * Base interface for symmetric encryption ciphers.
 */
interface CipherInterface
{
    /**
     * Encrypts the provided data with the given key, nonce, and additional authenticated data.
     *
     * @param string $data Plaintext to encrypt.
     * @param string $key Secret encryption key (sensitive).
     * @param string $nonce Initialization vector or nonce.
     * @param string $aad Additional authenticated data.
     *
     * @throws EncryptionException If encryption fails.
     *
     * @return string Ciphertext.
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce = '',
        string $aad = '',
    ): string;

    /**
     * Decrypts the provided ciphertext with the given key, nonce, and additional authenticated data.
     *
     * @param string $data Ciphertext to decrypt.
     * @param string $key Secret encryption key (sensitive).
     * @param string $nonce Nonce used during encryption.
     * @param string $aad Additional authenticated data (must match the value used during encryption).
     *
     * @throws EncryptionException If decryption fails.
     *
     * @return string Decrypted plaintext.
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $key,
        string $nonce = '',
        string $aad = '',
    ): string;

    /**
     * @return int Key size in bytes.
     *
     * @psalm-return int<1, max>
     */
    public function getKeySize(): int;

    /**
     * @return int Nonce size in bytes (may be 0 if the cipher does not use a nonce).
     *
     * @psalm-return int<0, max>
     */
    public function getNonceSize(): int;

    /**
     * @return int Overhead size in bytes.
     *
     * @psalm-return int<0, max>
     */
    public function getOverheadSize(): int;
}
