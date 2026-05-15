<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use Yiisoft\Strings\StringHelper;
use function
    random_bytes;

/**
 * Session‑oriented encryption (single key derived per message, no key wrapping).
 * A fresh data encryption key (DEK) is derived from the secret and a random salt.
 * This is suitable for encrypting large amounts of data in a single session.
 */
final readonly class SessionCryptor implements CryptorInterface
{
    /**
     * @psalm-var int<1, max>
     */
    private int $keySize;

    /**
     * @psalm-var int<1, max>
     */
    private int $nonceSize;

    private int $keyNonceSize;

    /**
     * @param CipherInterface $cipher Low‑level cipher
     * @param KdfInterface $kdf Key derivation function
     */
    public function __construct(
        private CipherInterface $cipher,
        private KdfInterface $kdf,
    ) {
        $this->keySize = $this->cipher->getKeySize();
        $this->nonceSize = $this->cipher->getNonceSize();
        $this->keyNonceSize = $this->keySize + $this->nonceSize;
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
        $keySalt = random_bytes($this->keySize);
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
        if (StringHelper::byteLength($data) < $this->keyNonceSize) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $keySalt = StringHelper::byteSubstring($data, 0, $this->keySize);
        $dataNonce = StringHelper::byteSubstring($data, $this->keySize, $this->nonceSize);
        $dataEncrypted = StringHelper::byteSubstring($data, $this->keyNonceSize);

        $dek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $decrypted = $this->cipher->decrypt($dataEncrypted, $dek, $dataNonce);

        return $decrypted;
    }
}
