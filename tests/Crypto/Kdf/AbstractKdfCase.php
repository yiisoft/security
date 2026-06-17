<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Kdf;

use RuntimeException;
use Stringable;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Strings\StringHelper;

abstract class AbstractKdfCase extends TestCase
{
    abstract protected function createKdfInstance(?string $hashAlgo = null, string|Stringable $hashStaticSalt = ''): KdfInterface;

    abstract public static function dataProviderAlgos(): iterable;

    abstract public static function dataProviderKeyValues(): iterable;

    public function testDeriveSuccess(): void
    {
        $kdf = $this->createKdfInstance();
        $keySize = 32;
        $secret = random_bytes($keySize);
        $salt = random_bytes($kdf->getSaltSize());
        $key = $kdf->derive($secret, $keySize, 'test-context', $salt);

        $this->assertSame($keySize, StringHelper::byteLength($key));
        $this->assertNotSame($secret, $key);
    }

    #[DataProvider('dataProviderKeyValues')]
    public function testKeyValues(string $hashAlgo, string $secret, int $keySize, string $context, string $salt, string $key): void
    {
        $kdf = $this->createKdfInstance($hashAlgo);

        $secret = hex2bin(preg_replace('{\s+}', '', $secret));
        $salt = hex2bin(preg_replace('{\s+}', '', $salt));
        $key = hex2bin(preg_replace('{\s+}', '', $key));

        $this->assertSame($key, $kdf->derive($secret, $keySize, $context, $salt));
    }

    #[DataProvider('dataProviderAlgos')]
    public function testDeriveWithCustomAlgorithm(string $hashAlgo, int $keySize): void
    {
        $kdf = $this->createKdfInstance($hashAlgo);
        $secret = random_bytes($keySize);
        $salt = random_bytes($kdf->getSaltSize());

        $key = $kdf->derive($secret, $keySize, 'test-context', $salt);

        $this->assertSame($keySize, StringHelper::byteLength($key));
    }

    public function testDeriveWithHashStaticSalt(): void
    {
        $staticSalt = random_bytes(32);
        $kdf1 = $this->createKdfInstance(hashStaticSalt: $staticSalt);
        $kdf2 = $this->createKdfInstance(hashStaticSalt: new StringableParam($staticSalt));
        $keySize = 32;
        $secret = random_bytes($keySize);
        $salt = random_bytes($kdf1->getSaltSize());
        $key1 = $kdf1->derive($secret, $keySize, 'test-context', $salt);
        $key2 = $kdf2->derive($secret, $keySize, 'test-context', $salt);

        $this->assertSame($keySize, StringHelper::byteLength($key1));
        $this->assertSame($keySize, StringHelper::byteLength($key2));
        $this->assertNotSame($secret, $key1);
        $this->assertNotSame($secret, $key2);
        $this->assertSame($key1, $key2);
    }

    public function testSameParametersProduceSameKey(): void
    {
        $kdf = $this->createKdfInstance();
        $keySize = 64;
        $secret = random_bytes($keySize);
        $salt = random_bytes($kdf->getSaltSize());

        $key1 = $kdf->derive($secret, $keySize, 'test-context', $salt);
        $key2 = $kdf->derive($secret, $keySize, 'test-context', $salt);

        $this->assertSame($key1, $key2);
    }

    public function testDifferentParamsProducesDifferentKey(): void
    {
        $kdf = $this->createKdfInstance();
        $keySize = 32;
        $secret = random_bytes($keySize);
        $secret2 = random_bytes($keySize);
        $salt1 = random_bytes($kdf->getSaltSize());
        $salt2 = random_bytes($kdf->getSaltSize());

        // different salt
        $key11 = $kdf->derive($secret, $keySize, 'test-context', $salt1);
        $key12 = $kdf->derive($secret, $keySize, 'test-context', $salt2);
        $this->assertNotSame($key11, $key12);

        // different context
        $key21 = $kdf->derive($secret, $keySize, 'context-1', $salt1);
        $key22 = $kdf->derive($secret, $keySize, 'context-2', $salt1);
        $this->assertNotSame($key21, $key22);

        // different secret
        $key31 = $kdf->derive($secret, $keySize, 'test-context', $salt1);
        $key32 = $kdf->derive($secret2, $keySize, 'test-context', $salt1);
        $this->assertNotSame($key31, $key32);
    }

    public function testInvalidHashAlgoThrowsException(): void
    {
        $this->expectException(RuntimeException::class);
        $this->createKdfInstance('Non-Existing-Algorithm');
    }

    public function testInvalidSizeThrowsException(): void
    {
        $kdf = $this->createKdfInstance();

        $this->expectException(EncryptionException::class);
        $kdf->derive('test-secret', -1, 'test-context', 'test-salt');
    }

    public function testSaltTooShortThrowsException(): void
    {
        $kdf = $this->createKdfInstance();
        $salt = random_bytes($kdf->getSaltSize() - 1);

        $this->expectException(EncryptionException::class);
        $kdf->derive(random_bytes(32), 32, 'test-context', $salt);
    }

    public function testSaltTooLongThrowsException(): void
    {
        $kdf = $this->createKdfInstance();
        $salt = random_bytes($kdf->getSaltSize() + 1);

        $this->expectException(EncryptionException::class);
        $kdf->derive(random_bytes(32), 32, 'test-context', $salt);
    }

    public function testGetSizes(): void
    {
        $cipher = $this->createKdfInstance();
        $keySize = $cipher->getSaltSize();

        $this->assertIsInt($keySize);
        $this->assertGreaterThanOrEqual(0, $keySize);
    }
}
