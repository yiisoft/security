<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Cipher;

use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypto\EncryptionException;

trait CipherWithNonceTrait
{
    #[DataProvider('dataProviderCiphers')]
    public function testEncryptWithWrongNonceSizeThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize() + 1); // wrong nonce size
        $plaintext = $this->getPlainText();

        $this->expectException(EncryptionException::class);
        $cipherInstance->encrypt($plaintext, $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongNonceSizeThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $key, $nonce . 'X'); // wrong nonce
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongNonceThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $wrongNonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = $this->getPlainText();

        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $key, $wrongNonce);
    }
}
