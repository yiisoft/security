<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use function
    mb_substr,
    random_bytes;

/**
 * Envelope encryption (key wrapping) using a KDF to derive a Key Encryption Key (KEK)
 * and a random Data Encryption Key (DEK). The DEK is encrypted with the KEK and stored
 * together with the ciphertext.
 *
 * This scheme enables secure handling of long‑term secrets: the DEK is fresh for each
 * encryption, and the KEK never touches the actual data payload.
 *
 * @psalm-immutable
 */
final readonly class EnvelopeCryptor implements CryptorInterface
{
    private int $nonceSize;
    private int $keySize;
    private int $tagSize;

    private int $keyNonceSize;
    private int $encKeyNonceSize;
    private int $prefixSize;

    /**
     * @param AeadCipherInterface $cipher AEAD cipher (e.g., AES-256-GCM)
     * @param KdfInterface $kdf Key derivation function (used to derive KEK from secret)
     */
    public function __construct(
        private AeadCipherInterface $cipher,
        private KdfInterface $kdf,
    ) {
        $this->nonceSize = $this->cipher->getNonceSize();
        $this->keySize = $this->cipher->getKeySize();
        $this->tagSize = $this->cipher->getTagSize();

        $this->keyNonceSize = $this->keySize + $this->nonceSize;
        $this->encKeyNonceSize = $this->keyNonceSize + $this->tagSize;
        $this->prefixSize = $this->keyNonceSize + $this->encKeyNonceSize;
    }

    /**
     * {@inheritdoc}
     *
     * Structure: keySalt (keySize) || dekNonce (nonceSize) ||
     *            encrypted(dek || dataNonce) (keyNonceSize + tagSize) ||
     *            encrypted(data) (variable + tag)
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        $keySalt = random_bytes($this->keySize);
        $dek = random_bytes($this->keySize);
        $dekNonce = random_bytes($this->nonceSize);
        $dataNonce = random_bytes($this->nonceSize);

        $kek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $dekEncrypted = $this->cipher->encrypt($dek . $dataNonce, $kek, $dekNonce);
        $dataEncrypted = $this->cipher->encrypt($data, $dek, $dataNonce);

        // keySalt || dekNonce || cipher(dek + dataNonce) || tag || ciphertext || tag
        return $keySalt.$dekNonce.$dekEncrypted . $dataEncrypted;
        //return $keySalt.$dekNonce.$dekEncrypted . $dataNonce.$dataEncrypted;
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
        if (mb_strlen($data, '8bit') < $this->prefixSize) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $keySalt = mb_substr($data, 0, $this->keySize, '8bit');
        $dekNonce = mb_substr($data, $this->keySize, $this->nonceSize, '8bit');
        $encDekWithNonce = mb_substr($data, $this->keyNonceSize, $this->encKeyNonceSize, '8bit');
        $dataEncrypted = mb_substr($data, $this->prefixSize, null, '8bit');

        $kek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $dekWithNonce = $this->cipher->decrypt($encDekWithNonce, $kek, $dekNonce);
        $decrypted = $this->cipher->decrypt($dataEncrypted, mb_substr($dekWithNonce, 0, $this->keySize, '8bit'), mb_substr($dekWithNonce, $this->keySize, null, '8bit'));

        return $decrypted;
    }
}
