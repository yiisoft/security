<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;
use function
    mb_substr,
    random_bytes;

final readonly class EnvelopeCryptor implements CryptorInterface
{
    private int $nounceSize;
    private int $keySize;
    private int $tagSize;

    private int $keyNounceSize;
    private int $encKeyNounceSize;
    private int $prefixSize;

    /**
     * @param string $cipher The cipher to use for encryption and decryption.
     * @param string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512. @see https://php.net/manual/en/function.hash-algos.php
     */
    public function __construct(
        private AeadCipherInterface $cipher,
        private KdfInterface $kdf,
    ) {
        $this->nounceSize = $this->cipher->getNounceSize();
        $this->keySize = $this->cipher->getKeySize();
        $this->tagSize = $this->cipher->getTagSize();

        $this->keyNounceSize = $this->keySize + $this->nounceSize;
        $this->encKeyNounceSize = $this->keyNounceSize + $this->tagSize;
        $this->prefixSize = $this->keyNounceSize + $this->encKeyNounceSize;
    }

    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        $keySalt = random_bytes($this->keySize);
        $dek = random_bytes($this->keySize);
        $dekNounce = random_bytes($this->nounceSize);
        $dataNounce = random_bytes($this->nounceSize);

        $kek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $dekEncrypted = $this->cipher->encrypt($dek . $dataNounce, $kek, $dekNounce);
        $dataEncrypted = $this->cipher->encrypt($data, $dek, $dataNounce);

        // keySalt || dekNounce || cipher(dek + dataNounce) || tag || ciphertext || tag
        return $keySalt.$dekNounce.$dekEncrypted . $dataEncrypted;
        //return $keySalt.$dekNounce.$dekEncrypted . $dataNounce.$dataEncrypted;
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
        $dekNounce = mb_substr($data, $this->keySize, $this->nounceSize, '8bit');
        $encDekWithNounce = mb_substr($data, $this->keyNounceSize, $this->encKeyNounceSize, '8bit');
        $dataEncrypted = mb_substr($data, $this->prefixSize, null, '8bit');

        $kek = $this->kdf->createKey($secret, $this->keySize, $context, $keySalt);
        $dekWithNounce = $this->cipher->decrypt($encDekWithNounce, $kek, $dekNounce);
        $decrypted = $this->cipher->decrypt($dataEncrypted, mb_substr($dekWithNounce, 0, $this->keySize, '8bit'), mb_substr($dekWithNounce, $this->keySize, null, '8bit'));

        return $decrypted;
    }
}
