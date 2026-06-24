<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Kdf;

use RuntimeException;
use Stringable;
use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Security\Crypto\Kdf\KdfKey;

final class KdfKeyTest extends AbstractKdfCase
{
    public static function dataProviderKeyValues(): iterable
    {
        yield [
            'sha256',
            '263d2461b6464bbc898ffa385f9d4c1a8f5a1cf0e2d27c4499516142e0542125',
            32,
            'test-context',
            'ae8cbb001c062cd2c00ed6956842dc4d36f5ce3e9b6b607e46e47018841b29d7',
            'af2da95bc3da38c4d5321779001f31119151aabdb7e553ae2534c17bd48897ac',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'test-context',
            '7f22a943efd3537ef9e0dc98e7031d9f71b16868ccc0aafe110ab32f7e54db61',
            '5a64ca7627ad8c93254123dda29e631110dea2276db55e0cf273518b367f0a0a38cb307970458cbc6e78d10d9d5b5ead975cd38a8b086ab8c776e4605ab82386',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'test-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a44c3f7b9ea061551529556ac70dd0cfeb',
            '1d8a2011276aadcf62e4f999386fe9585a4e3797f55a5c43efda4b9a211c75c0',
        ];
    }

    public static function dataProviderEmptyStaticSaltKeyValues(): iterable
    {
        yield [
            'sha256',
            '263d2461b6464bbc898ffa385f9d4c1a8f5a1cf0e2d27c4499516142e0542125',
            32,
            'test-context',
            '50320fc7d6a85c6bb631a10475bd27e0d49892c509041692917c19b0451f98b2',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'test-context',
            'f2b0f6e277232602dfe7588c37850f646c97b4fd8fb120ecf6b28a1b2548939f06e1941feee58a834ad8644b4f62f140a12d001ed6bb297c7b2c8386e0ef249e',
        ];
    }

    public function testDifferentParamsAndEmptySaltProducesDifferentKey(): void
    {
        $kdf = new KdfKey(saltSize: 0);
        $keySize = 32;
        $secret = random_bytes($keySize);
        $secret2 = random_bytes($keySize);

        // different context
        $key21 = $kdf->derive($secret, $keySize, 'context-1');
        $key22 = $kdf->derive($secret, $keySize, 'context-2');
        $this->assertNotSame($key21, $key22);

        // different secret
        $key31 = $kdf->derive($secret, $keySize, 'test-context');
        $key32 = $kdf->derive($secret2, $keySize, 'test-context');
        $this->assertNotSame($key31, $key32);
    }

    public function testDifferentStaticSaltProducesDifferentKey(): void
    {
        $kdf1 = new KdfKey(hashStaticSalt: random_bytes(32), saltSize: 0);
        $kdf2 = new KdfKey(hashStaticSalt: random_bytes(32), saltSize: 0);
        $keySize = 32;
        $secret = random_bytes($keySize);

        $key1 = $kdf1->derive($secret, $keySize, 'test-context');
        $key2 = $kdf2->derive($secret, $keySize, 'test-context');
        $this->assertNotSame($key1, $key2);
    }

    public function testSaltSizeValid(): void
    {
        $kdf = new KdfKey(saltSize: 24);
        $this->assertSame(24, $kdf->getSaltSize());
    }

    public function testInvalidSecretThrowsException(): void
    {
        $kdf = $this->createKdfInstance();

        $this->expectException(EncryptionException::class);
        $kdf->derive('', 32, 'test-context', 'test-salt');
    }

    public function testInvalidStaticSaltThrowsException(): void
    {
        $this->expectException(RuntimeException::class);
        $this->createKdfInstance(hashAlgo: 'sha256', hashStaticSalt: random_bytes(31));
    }

    public function testInvalidSaltSizeThrowsException(): void
    {
        $kdf = new KdfKey(saltSize: -1);

        $this->expectException(EncryptionException::class);
        $kdf->derive('test-secret', 32, 'test-context', 'test-salt');
    }

    #[DataProvider('dataProviderEmptyStaticSaltKeyValues')]
    public function testEmptyStaticSaltDerivesExpectedKey(string $hashAlgo, string $secret, int $keySize, string $context, string $key): void
    {
        $kdf = new KdfKey(hashAlgo: $hashAlgo, hashStaticSalt: '', saltSize: 0);
        $secret = hex2bin(preg_replace('{\s+}', '', $secret));
        $key = hex2bin(preg_replace('{\s+}', '', $key));

        $this->assertSame($key, $kdf->derive($secret, $keySize, $context));
    }

    protected function createKdfInstance(?string $hashAlgo = null, string|Stringable $hashStaticSalt = ''): KdfInterface
    {
        return $hashAlgo
            ? new KdfKey(hashAlgo: $hashAlgo, hashStaticSalt: $hashStaticSalt)
            : new KdfKey(hashStaticSalt: $hashStaticSalt);
    }
}
