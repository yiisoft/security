<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use Yiisoft\Strings\StringHelper;

use function random_bytes;

/**
 * Session‑oriented encryption (single key derived per message, no key wrapping).
 * A fresh data encryption key (DEK) is derived from the secret and a random salt.
 * This is suitable for encrypting large amounts of data in a single session.
 */
final class SessionCryptor implements CryptorInterface
{
    /**
     * @psalm-var int<1, max>
     */
    private readonly int $keySize;

    /**
     * @psalm-var int<1, max>
     */
    private readonly int $nonceSize;

    /**
     * @psalm-var int<1, max>
     */
    private readonly int $saltSize;

    private readonly int $saltNonceSize;

    /**
     * @param CipherInterface $cipher Low‑level cipher
     * @param KdfInterface $kdf Key derivation function
     */
    public function __construct(
        private readonly CipherInterface $cipher,
        private readonly KdfInterface $kdf,
    ) {
        $this->keySize = $this->cipher->getKeySize();
        /** @psalm-var int<1, max> */
        $this->nonceSize = $this->cipher->getNonceSize();
        $this->saltSize = $this->kdf->getSaltSize();
        $this->saltNonceSize = $this->saltSize + $this->nonceSize;
    }

    /**
     * {@inheritdoc}
     *
     * Structure: keySalt || nonce || ciphertext (with tag for AEAD ciphers)
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        $keySalt = random_bytes($this->saltSize);
        $dataNonce = random_bytes($this->nonceSize);

        $dek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $dataEncrypted = $this->cipher->encrypt($data, $dek, $dataNonce);

        // keySalt || nonce || ciphertext || tag
        return $keySalt . $dataNonce . $dataEncrypted;
    }

    /**
     * {@inheritdoc}
     *
     * @throws EncryptionException If decryption fails.
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        if (StringHelper::byteLength($data) < $this->saltNonceSize) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $keySalt = StringHelper::byteSubstring($data, 0, $this->saltSize);
        $dataNonce = StringHelper::byteSubstring($data, $this->saltSize, $this->nonceSize);
        $dataEncrypted = StringHelper::byteSubstring($data, $this->saltNonceSize);

        $dek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);

        return $this->cipher->decrypt($dataEncrypted, $dek, $dataNonce);
    }
}
