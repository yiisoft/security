<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\CipherInterface;

/**
 * @abstract
 */
abstract class AbstractCipherCase extends TestCase
{
    abstract protected function createCipherInstance(string $cipher): CipherInterface;

    abstract public static function dataProviderCiphers(): iterable;

    abstract public static function dataProviderEncrypted(): iterable;

    #[DataProvider('dataProviderCiphers')]
    public function testEncryptDecryptSuccess(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = 'test-plain-data';

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

        $this->assertEquals($encrypted, $cipherInstance->encrypt($data, $key, $nonce));
        $this->assertEquals($data, $cipherInstance->decrypt($encrypted, $key, $nonce));
    }

    public function testInvalidCipherThrowsException(): void
    {
        $this->expectException(RuntimeException::class);
        $this->createCipherInstance('Non-Existing-Cipher');
    }

    #[DataProvider('dataProviderCiphers')]
    public function testEncryptWithWrongKeySizeThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize() + 1); // неверный размер
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = 'test-plain-data';

        $this->expectException(EncryptionException::class);
        $cipherInstance->encrypt($plaintext, $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testEncryptWithWrongNonceSizeThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize() + 1); // неверный размер
        $plaintext = 'test-plain-data';

        $this->expectException(EncryptionException::class);
        $cipherInstance->encrypt($plaintext, $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongKeySizeThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = 'test-plain-data';
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $key . 'X', $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongNonceSizeThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize()); // неверный размер
        $plaintext = 'test-plain-data';
        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $key, $nonce . 'X');
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithTamperedCiphertextThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = 'test-plain-data';

        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);
        $tampered = substr_replace($ciphertext, 'XXX', -3);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($tampered, $key, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongKeyThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $wrongKey = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = 'test-plain-data';

        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $wrongKey, $nonce);
    }

    #[DataProvider('dataProviderCiphers')]
    public function testDecryptWithWrongNonceThrowsException(string $cipher): void
    {
        $cipherInstance = $this->createCipherInstance($cipher);
        $key = random_bytes($cipherInstance->getKeySize());
        $nonce = random_bytes($cipherInstance->getNonceSize());
        $wrongNonce = random_bytes($cipherInstance->getNonceSize());
        $plaintext = 'test-plain-data';

        $ciphertext = $cipherInstance->encrypt($plaintext, $key, $nonce);

        $this->expectException(EncryptionException::class);
        $cipherInstance->decrypt($ciphertext, $key, $wrongNonce);
    }
}
