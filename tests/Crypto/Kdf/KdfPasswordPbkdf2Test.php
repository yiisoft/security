<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Kdf;

use RuntimeException;
use Stringable;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Security\Crypto\Kdf\KdfPasswordPbkdf2;

final class KdfPasswordPbkdf2Test extends AbstractKdfCase
{
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
            'test-context',
            'ae8cbb001c062cd2c00ed6956842dc4d36f5ce3e9b6b607e46e47018841b29d7',
            '9b203ca13de4bae280fcb5b0af75696f5828e8e2135b995ddc20a769517f9141',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'test-context',
            '7f22a943efd3537ef9e0dc98e7031d9f71b16868ccc0aafe110ab32f7e54db61',
            'aaca6ad950cd6e9b187abf8fd3e67c9d6f199222d84e5f1a8c172b3d4e880bbe951e2ea6f50eeb4c660393e8b6a1e420bd901453a103d16af3b6fff3da574045',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'test-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a44c3f7b9ea061551529556ac70dd0cfeb',
            '5f38ecf98ed67feaeced2bc83d2a41e47a2850e353297f916a0b551b1ecc115f',
        ];
    }

    public function testConstructorThrowsExceptionWhenIterationsLessThanOne(): void
    {
        $this->expectException(RuntimeException::class);
        new KdfPasswordPbkdf2(iterations: 0);
    }

    protected function createKdfInstance(?string $hashAlgo = null, string|Stringable $hashStaticSalt = ''): KdfInterface
    {
        return $hashAlgo
            ? new KdfPasswordPbkdf2(hashAlgo: $hashAlgo, iterations: 100_000, hashStaticSalt: $hashStaticSalt)
            : new KdfPasswordPbkdf2(iterations: 100_000, hashStaticSalt: $hashStaticSalt);
    }
}
