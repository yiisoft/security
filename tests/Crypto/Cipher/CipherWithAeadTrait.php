<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Cipher;

use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypto\EncryptionException;

trait CipherWithAeadTrait
{
    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithTagTooLongThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext . 'X', $key, $nonce); // wrong tag
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithTagTooShortThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt(substr($ciphertext, 0, -1), $key, $nonce); // wrong tag
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithTagRemovedThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);
        $tagSize = $cipherInstance->getOverheadSize();

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt(substr($ciphertext, 0, -$tagSize), $key, $nonce); // remove auth tag
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongTagThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);
        $tagSize = $cipherInstance->getOverheadSize();

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt(substr_replace($ciphertext, random_bytes($tagSize), -$tagSize), $key, $nonce); // wrong tag
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithFakeCiphertextThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = $this->getPlainText();
        $fakePlaintext = $this->getPlainText() . '-fake';
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);
        $fakeCiphertext = $cipherInstance->encrypt($fakePlaintext, $key, $nonce);
        $tagSize = $cipherInstance->getOverheadSize();
        $tag = substr($ciphertext, -$tagSize);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt(substr_replace($fakeCiphertext, $tag, -$tagSize), $key, $nonce); // fake ciphertext
    }
}
