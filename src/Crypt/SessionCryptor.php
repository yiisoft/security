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
    private int $nonceSize;

    private int $keyNonceSize;

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     * @param string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512. @see https://php.net/manual/en/function.hash-algos.php
     */
    public function __construct(
        private CipherInterface $cipher,
        private KdfInterface $kdf,
    ) {
        $this->keySize = $this->cipher->getKeySize();
        $this->nonceSize = $this->cipher->getNonceSize();
        $this->keyNonceSize = $this->keySize + $this->nonceSize;
    }

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
