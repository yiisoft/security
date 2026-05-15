<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use Yiisoft\Strings\StringHelper;
use function
    random_bytes;

/**
 * Envelope encryption (key wrapping) using a KDF to derive a Key Encryption Key (KEK)
 * and a random Data Encryption Key (DEK). The DEK is encrypted with the KEK and stored
 * together with the ciphertext.
 *
 * This scheme enables secure handling of long‑term secrets: the DEK is fresh for each
 * encryption, and the KEK never touches the actual data payload.
 */
final readonly class EnvelopeCryptor implements CryptorInterface
{
    /**
     * @psalm-var int<1, max>
     */
    private int $keySize;

    /**
     * @psalm-var int<1, max>
     */
    private int $nonceSize;

    /**
     * @psalm-var int<1, max>
     */
    private int $tagSize;

    private int $keyNonceSize;
    private int $encKeySize;
    private int $keyNonceEncKeySize;
    private int $prefixSize;

    /**
     * @param AeadCipherInterface $cipher AEAD cipher (e.g., AES-256-GCM)
     * @param KdfInterface $kdf Key derivation function (used to derive KEK from secret)
     */
    public function __construct(
        private AeadCipherInterface $cipher,
        private KdfInterface $kdf,
    ) {
        $this->keySize = $this->cipher->getKeySize();
        $this->nonceSize = $this->cipher->getNonceSize();
        $this->tagSize = $this->cipher->getTagSize();

        $this->keyNonceSize = $this->keySize + $this->nonceSize;
        $this->encKeySize = $this->keySize + $this->tagSize;
        $this->keyNonceEncKeySize = $this->keyNonceSize + $this->encKeySize;
        $this->prefixSize = $this->keyNonceEncKeySize + $this->nonceSize;
    }

    /**
     * {@inheritdoc}
     *
     * Structure: keySalt (keySize) || dekNonce (nonceSize) ||
     *            encrypted(dek) (keySize + tagSize) ||
     *            dataNonce (nonceSize) || encrypted(data) (variable + tagSize)
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
        $dekEncrypted = $this->cipher->encrypt($dek, $kek, $dekNonce);
        $dataEncrypted = $this->cipher->encrypt($data, $dek, $dataNonce);

        // keySalt || dekNonce || cipherdek || tag || dataNonce || ciphertext || tag
        return $keySalt . $dekNonce . $dekEncrypted . $dataNonce . $dataEncrypted;
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
        if (StringHelper::byteLength($data) < $this->prefixSize) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $keySalt = StringHelper::byteSubstring($data, 0, $this->keySize);
        $dekNonce = StringHelper::byteSubstring($data, $this->keySize, $this->nonceSize);
        $encDek = StringHelper::byteSubstring($data, $this->keyNonceSize, $this->encKeySize);
        $dataNonce = StringHelper::byteSubstring($data, $this->keyNonceEncKeySize, $this->nonceSize);
        $dataEncrypted = StringHelper::byteSubstring($data, $this->prefixSize);

        $kek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $dek = $this->cipher->decrypt($encDek, $kek, $dekNonce);
        $decrypted = $this->cipher->decrypt($dataEncrypted, $dek, $dataNonce);

        return $decrypted;
    }
}
