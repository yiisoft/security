<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use function
    mb_substr,
    random_bytes;

final readonly class EnvelopeCryptor implements CryptorInterface
{
    private int $nonceSize;
    private int $keySize;
    private int $tagSize;

    private int $keyNonceSize;
    private int $encKeyNonceSize;
    private int $prefixSize;

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     * @param string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512. @see https://php.net/manual/en/function.hash-algos.php
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
