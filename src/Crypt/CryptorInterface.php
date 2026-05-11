<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;

interface CryptorInterface
{
    /**
     * Encrypts data.
     *
     * @param string $data data to be encrypted
     * @param bool $passwordBased set true to use password-based key derivation
     * @param string $secret the encryption password or key
     * @param string $info context/application specific information, e.g. a user ID
     * See [RFC 5869 Section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2) for more details.
     *
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL error
     *
     * @return string the encrypted data as byte string
     *
     * @see decrypt()
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string;

    /**
     * Decrypts data.
     *
     * @param string $data encrypted data to be decrypted.
     * @param bool $passwordBased set true to use password-based key derivation
     * @param string $secret the decryption password or key
     * @param string $info context/application specific information, @see encrypt()
     *
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL errors
     * @throws AuthenticationException on authentication failure
     *
     * @return string the decrypted data
     *
     * @see encrypt()
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string;
}
