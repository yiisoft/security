<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Cipher;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Security\Crypto\EncryptionException;

/**
 * @abstract
 */
abstract class AbstractCipherCase extends TestCase
{
    abstract public static function dataProviderCiphers(): iterable;

    abstract public static function dataProviderEncrypted(): iterable;

    #[DataProvider('dataProviderCiphers')]
    public function testEncryptDecryptSuccess(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $plaintext = $this->getPlainText();
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';

        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);
        $this->assertNotSame($plaintext, $ciphertext);

        $decrypted = $cipherInstance->decrypt($ciphertext, $key, $nonce);
        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * @param string $cipher
     * @param string $key encryption key hex string
     * @param string $nonce encryption nonce hex string
     * @param string $data plaintext data
     * @param string $encrypted ciphertext hex string
     */
    #[DataProvider('dataProviderEncrypted')]
    public function testEncrypted(string $cipher, string $key, string $nonce, string $data, string $encrypted): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);

        $key = hex2bin(preg_replace('{\s+}', '', $key));
        $nonce = hex2bin(preg_replace('{\s+}', '', $nonce));
        $encrypted = hex2bin(preg_replace('{\s+}', '', $encrypted));

        $this->assertSame($encrypted, $cipherInstance->encrypt($data, $key, $nonce));
        $this->assertSame($data, $cipherInstance->decrypt($encrypted, $key, $nonce));
    }

    public function testInvalidCipherThrowsException(): void
    {
        $this->expectException(RuntimeException::class);
        $this->createCipherInstance('Non-Existing-Cipher');
    }

    #[DataProvider('dataProviderCiphers')]
    public function testEncryptWithKeyTooShortThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $plaintext = $this->getPlainText();
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';

        $key = random_bytes($cipherInstance->getKeySize() - 1); // wrong key size

        $this->expectException(EncryptionException::class);
        $cipherInstance->encrypt($plaintext, $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testEncryptWithKeyTooLongThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $plaintext = $this->getPlainText();
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';

        $key = random_bytes($cipherInstance->getKeySize() + 1); // wrong key size

        $this->expectException(EncryptionException::class);
        $cipherInstance->encrypt($plaintext, $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testEncryptWithEmptyKeyThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $plaintext = $this->getPlainText();
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';

        $this->expectException(EncryptionException::class);
        $cipherInstance->encrypt($plaintext, '', $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithKeyTooLongThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $key . 'X', $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithKeyTooShortThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, substr($key, 1), $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithEmptyKeyThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, '', $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithCiphertextCorruptedThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt(substr_replace($ciphertext, 'XXX', -3), $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithCiphertextTruncatedThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';
        $plaintext = $this->getPlainText();
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt(substr($ciphertext, 1), $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongKeyThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $wrongKey = random_bytes($cipherInstance->getKeySize());
        $nonce = $cipherInstance->getNonceSize() ? random_bytes($cipherInstance->getNonceSize()) : '';
        $plaintext = $this->getPlainText();

        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $wrongKey, $nonce);
    }

    public function testGetSizes(): void
    {
        $cipher = $this->createCipherInstance();

        $this->assertIsInt($cipher->getKeySize());
        $this->assertIsInt($cipher->getNonceSize());
        $this->assertIsInt($cipher->getOverheadSize());
    }

    abstract protected function createCipherInstance(?string $cipher = null): CipherInterface;

    abstract protected static function getPlainText(): string;
}
