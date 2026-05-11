<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use function
    mb_substr,
    random_bytes;

/**
 * Session‑oriented encryption (single key derived per message, no key wrapping).
 * A fresh data encryption key (DEK) is derived from the secret and a random salt.
 * This is suitable for encrypting large amounts of data in a single session.
 *
 * @psalm-immutable
 */
final readonly class SessionCryptor implements CryptorInterface
{
    private int $keySize;
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
        if (mb_strlen($data, '8bit') < $this->keyNonceSize) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $keySalt = mb_substr($data, 0, $this->keySize, '8bit');
        $dataNonce = mb_substr($data, $this->keySize, $this->nonceSize, '8bit');
        $dataEncrypted = mb_substr($data, $this->keyNonceSize, null, '8bit');

        $dek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $decrypted = $this->cipher->decrypt($dataEncrypted, $dek, $dataNonce);

        return $decrypted;
    }
}
