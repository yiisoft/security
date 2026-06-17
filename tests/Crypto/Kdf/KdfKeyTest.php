<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Kdf;

use Stringable;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Security\Crypto\Kdf\KdfKey;

final class KdfKeyTest extends AbstractKdfCase
{
    protected function createKdfInstance(?string $hashAlgo = null, string|Stringable $hashStaticSalt = ''): KdfInterface
    {
        return $hashAlgo
            ? new KdfKey(hashAlgo: $hashAlgo, hashStaticSalt: $hashStaticSalt)
            : new KdfKey(hashStaticSalt: $hashStaticSalt);
    }

    public static function dataProviderAlgos(): iterable
    {
        yield ['sha256', 32];
        yield ['sha512', 64];
        yield ['sha3-256', 32];
    }

    public static function dataProviderKeyValues(): iterable
    {
        yield [
            'sha256',
            '263d2461b6464bbc898ffa385f9d4c1a8f5a1cf0e2d27c4499516142e0542125',
            32,
            'text-context',
            'ae8cbb001c062cd2c00ed6956842dc4d36f5ce3e9b6b607e46e47018841b29d7',
            '465b57608c27082a09e197024a5d0a703017fe12f6fe7f0219b652a6f5e27f3b',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'text-context',
            '7f22a943efd3537ef9e0dc98e7031d9f71b16868ccc0aafe110ab32f7e54db61',
            'db4d7ac9c6f656e0f7f0232d12993f7a1971568a2ce0a9bac97039a24beb914bd984685796a418e91d3e1a2f325861fe0b88db5e5ad2a54de342592f5af0168e',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'text-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a44c3f7b9ea061551529556ac70dd0cfeb',
            '682b82147fe8f6cafa0fd6aeee12910bad20712ea93863289631a3cd6905ea5a',
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

        $key1 = $kdf1->derive($secret, $keySize, 'context');
        $key2 = $kdf2->derive($secret, $keySize, 'context');
        $this->assertNotSame($key1, $key2);
    }

    public function testInvalidSecretThrowsException(): void
    {
        $kdf = $this->createKdfInstance();

        $this->expectException(EncryptionException::class);
        $kdf->derive('', 32, 'test-context', 'test-salt');
    }
}
