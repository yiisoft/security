<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypto;

use SensitiveParameter;
use Yiisoft\Strings\StringHelper;

use function random_bytes;

/**
 * Session‑oriented encryption (single key derived per message, no key wrapping).
 * A fresh data encryption key (DEK) is derived from the secret and a random salt.
 * This is suitable for encrypting large amounts of data in a single session.
 *
 * The resulting ciphertext contains no built‑in authentication mechanism,
 * therefore the underlying cipher MUST be AEAD to provide integrity and authenticity.
 */
final readonly class KdfCryptor implements CryptorInterface
{
    /**
     * @psalm-var int<1, max>
     */
    private int $keySize;

    /**
     * @psalm-var int<0, max>
     */
    private int $nonceSize;

    /**
     * @psalm-var int<0, max>
     */
    private int $saltSize;

    private int $headerLength;

    /**
     * @param KdfInterface $kdf Key derivation function (used to derive DEK from secret + salt).
     * @param CipherInterface $cipher Low‑level cipher (must support AEAD).
     */
    public function __construct(
        private KdfInterface $kdf,
        private CipherInterface $cipher,
    ) {
        $this->keySize = $this->cipher->getKeySize();
        $this->nonceSize = $this->cipher->getNonceSize();
        $this->saltSize = $this->kdf->getSaltSize();
        $this->headerLength = $this->saltSize + $this->nonceSize;
    }

    /**
     * {@inheritdoc}
     *
     * Structure: salt || nonce || ciphertext (with tag for AEAD ciphers)
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = '',
    ): string {
        $kdfSalt = $this->saltSize ? random_bytes($this->saltSize) : '';
        $dataNonce = $this->nonceSize ? random_bytes($this->nonceSize) : '';

        $dek = $this->kdf->derive($secret, $this->keySize, $context, $kdfSalt);
        $dataEncrypted = $this->cipher->encrypt($data, $dek, $dataNonce);

        // kdfSalt || nonce || ciphertext || tag
        return $kdfSalt . $dataNonce . $dataEncrypted;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = '',
    ): string {
        if (StringHelper::byteLength($data) < $this->headerLength) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $kdfSalt = $this->saltSize ? StringHelper::byteSubstring($data, 0, $this->saltSize) : '';
        $dataNonce = $this->nonceSize ? StringHelper::byteSubstring($data, $this->saltSize, $this->nonceSize) : '';
        $dataEncrypted = StringHelper::byteSubstring($data, $this->headerLength);

        $dek = $this->kdf->derive($secret, $this->keySize, $context, $kdfSalt);

        return $this->cipher->decrypt($dataEncrypted, $dek, $dataNonce);
    }
}
