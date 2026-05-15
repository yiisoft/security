<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\KdfInterface;

abstract class AbstractKdfCase extends TestCase
{
    abstract protected function createKdfInstance(?string $hash = null): KdfInterface;

    abstract public static function dataProviderAlgos(): iterable;

    abstract public static function dataProviderKeyValues(): iterable;

    public function testCreateKeySuccess(): void
    {
        $kdf = $this->createKdfInstance();
        $keySize = 32;
        $secret = random_bytes($keySize);

        $key = $kdf->createKey($secret, $keySize, 'test-context', 'text-salt');

        $this->assertSame($keySize, strlen($key));
        $this->assertNotEmpty($key);
    }

    #[DataProvider('dataProviderKeyValues')]
    public function testKeyValues(string $algo, string $secret, int $keySize, string $context, string $salt, string $key): void
    {
        $kdf = $this->createKdfInstance($algo);

        
        $secret = hex2bin(preg_replace('{\s+}', '', $secret));
        $salt = hex2bin(preg_replace('{\s+}', '', $salt));
        $key = hex2bin(preg_replace('{\s+}', '', $key));

        $this->assertEquals($key, $kdf->createKey($secret, $keySize, $context, $salt));
    }

    #[DataProvider('dataProviderAlgos')]
    public function testCreateKeyWithCustomAlgorithm(string $algo, int $keySize): void
    {
        $kdf = $this->createKdfInstance($algo);
        $secret = random_bytes($keySize);

        $key = $kdf->createKey($secret, $keySize, 'test-context', 'test-salt');

        $this->assertSame($keySize, strlen($key));
    }

    public function testSameParametersProduceSameKey(): void
    {
        $kdf = $this->createKdfInstance();
        $keySize = 32;
        $secret = random_bytes($keySize);

        $key1 = $kdf->createKey($secret, $keySize, 'test-context', 'test-salt');
        $key2 = $kdf->createKey($secret, $keySize, 'test-context', 'test-salt');

        $this->assertSame($key1, $key2);
    }

    public function testDifferentParamsProducesDifferentKey(): void
    {
        $kdf = $this->createKdfInstance();
        $keySize = 32;
        $secret = random_bytes($keySize);
        $secret2 = random_bytes($keySize);

        $key11 = $kdf->createKey($secret, $keySize, 'test-context', 'test-salt-1');
        $key12 = $kdf->createKey($secret, $keySize, 'test-context', 'test-salt-2');
        $this->assertNotSame($key11, $key12);

        $key21 = $kdf->createKey($secret, $keySize, 'context-1', 'test-salt');
        $key22 = $kdf->createKey($secret, $keySize, 'context-2', 'test-salt');
        $this->assertNotSame($key21, $key22);

        $key31 = $kdf->createKey($secret, $keySize, 'test-context', 'test-salt');
        $key32 = $kdf->createKey($secret2, $keySize, 'test-context', 'test-salt');
        $this->assertNotSame($key31, $key32);
    }

    public function testInvalidAlgoThrowsException(): void
    {
        $this->expectException(RuntimeException::class);
        $this->createKdfInstance('Non-Existing-Algorithm');
    }

    public function testInvalidSizeThrowsException(): void
    {
        $kdf = $this->createKdfInstance();

        $this->expectException(EncryptionException::class);
        $kdf->createKey('test-secret', -1, 'test-context', 'test-salt');
    }
}
