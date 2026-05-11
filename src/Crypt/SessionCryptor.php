<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use function
    mb_substr,
    random_bytes;

final readonly class SessionCryptor implements CryptorInterface
{
    private int $keySize;
    private int $nounceSize;

    private int $keyNounceSize;

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     * @param string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512. @see https://php.net/manual/en/function.hash-algos.php
     */
    public function __construct(
        private CipherInterface $cipher,
        private KdfInterface $kdf,
    ) {
        $this->keySize = $this->cipher->getKeySize();
        $this->nounceSize = $this->cipher->getNounceSize();
        $this->keyNounceSize = $this->keySize + $this->nounceSize;
    }

    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        $keySalt = random_bytes($this->keySize);
        $dataNounce = random_bytes($this->nounceSize);

        $dek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $dataEncrypted = $this->cipher->encrypt($data, $dek, $dataNounce);

        // keySalt || nounce || ciphertext || tag
        return $keySalt . $dataNounce . $dataEncrypted;
    }

    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        if (mb_strlen($data, '8bit') < $this->keyNounceSize) {
            throw new EncryptionException('Encrypted data is too short.');
        }

        $keySalt = mb_substr($data, 0, $this->keySize, '8bit');
        $dataNounce = mb_substr($data, $this->keySize, $this->nounceSize, '8bit');
        $dataEncrypted = mb_substr($data, $this->keyNounceSize, null, '8bit');

        $dek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $decrypted = $this->cipher->decrypt($dataEncrypted, $dek, $dataNounce);

        return $decrypted;
    }
}
