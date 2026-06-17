<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\EnvelopeCryptor;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Strings\StringHelper;

final class EnvelopeCryptorWithSingleCipherTest extends TestCase
{
    public function testConstructWithSingleCipher(): void
    {
        $kdf = $this->getKdfStub();
        $cipher = $this->getCipherStub();
        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher);

        $plaintext = 'test-plain-data';

        $encrypted = $cryptor->encrypt($plaintext, 'test-secret', 'test-context');
        $decrypted = $cryptor->decrypt($encrypted, 'test-secret', 'test-context');

        $this->assertSame($plaintext, $decrypted);
    }

    public function testSingleCipherEncryptionIsRandomized(): void
    {
        $kdf = $this->getKdfStub();
        $cipher = $this->getCipherStub();
        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher);

        $enc1 = $cryptor->encrypt('test-plain-data', 'test-secret');
        $enc2 = $cryptor->encrypt('test-plain-data', 'test-secret');
        $this->assertNotSame($enc1, $enc2);
    }

    public function testSingleCipherWrongSecretThrowsException(): void
    {
        $kdf = $this->getKdfStub();
        $cipher = $this->getCipherStub();
        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher);

        $encrypted = $cryptor->encrypt('test-plain-data', 'correct');
        $this->expectException(EncryptionException::class);
        $cryptor->decrypt($encrypted, 'wrong');
    }

    public function testSingleCipherTooShortDataThrowsException(): void
    {
        $kdf = $this->getKdfStub();
        $cipher = $this->getCipherStub();
        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher);

        $this->expectException(EncryptionException::class);
        $cryptor->decrypt('short', 'secret');
    }

    private function getKdfStub(int $saltSize = 16): KdfInterface
    {
       return new class ($saltSize) implements KdfInterface
       {
            public function __construct(private readonly int $saltSize) {}

            public function derive(string $secret, int $keySize, string $context, string $salt = ''): string
            {
                $hash = hash('sha256', $secret . $context . $salt, true);

                return StringHelper::byteSubstring(str_repeat($hash, (int) ceil($keySize / 32)), 0, $keySize);
            }

            public function getSaltSize(): int
            {
               return $this->saltSize;
            }
       };
    }

    private function getCipherStub(int $keySize = 32, int $nonceSize = 12): CipherInterface
    {
        return new class ($keySize, $nonceSize) implements CipherInterface
        {
            // sha256 hash length
            private const TAG_SIZE = 32;

            public function __construct(
                private readonly int $keySize,
                private readonly int $nonceSize,
            ) {}

            public function encrypt(string $data, #[SensitiveParameter] string $key, string $nonce = '', string $aad = ''): string
            {
                $encrypted = $this->jgurdaCipher($data, $key);
                //echo $encrypted . PHP_EOL;
                return $encrypted . hash_hmac('sha256', $encrypted . $nonce, $key, true);
                //return $this->jgurdaCipher($data, $key) . str_repeat("\x20", $this->overheadSize);
            }

            public function decrypt(string $data, #[SensitiveParameter] string $key, string $nonce = '', string $aad = ''): string
            {
                $payloadLen = StringHelper::byteLength($data) - self::TAG_SIZE;
                if ($payloadLen < 0) {
                    throw new EncryptionException('Invalid data');
                }

                $storedData = StringHelper::byteSubstring($data, 0, -self::TAG_SIZE);
                $tag = StringHelper::byteSubstring($data, -self::TAG_SIZE);
                $expectedTag = hash_hmac('sha256', $storedData . $nonce, $key, true);

                if ($tag !== $expectedTag) {
                    throw new EncryptionException('Decryption failed');
                }

                return $this->jgurdaCipher($storedData, $key);
            }

            private function jgurdaCipher(string $text, string $key): string
            {
                return $text ^ str_repeat($key, StringHelper::byteLength($text));
            }

            public function getKeySize(): int
            {
                return $this->keySize;
            }

            public function getNonceSize(): int
            {
                return $this->nonceSize;
            }

            public function getOverheadSize(): int
            {
                return self::TAG_SIZE;
            }
        };
    }
}
