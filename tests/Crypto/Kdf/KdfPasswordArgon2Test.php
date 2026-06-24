<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Kdf;

use Stringable;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Security\Crypto\Kdf\KdfPasswordArgon2;

use function extension_loaded;

final class KdfPasswordArgon2Test extends AbstractKdfCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is required for these tests.');
        }
    }

    public static function dataProviderKeyValues(): iterable
    {
        yield [
            'sha256',
            '263d2461b6464bbc898ffa385f9d4c1a8f5a1cf0e2d27c4499516142e0542125',
            32,
            'test-context',
            'ae8cbb001c062cd2c00ed6956842dc4d',
            '0dd1df2a07aa3727520f1863b0f753d4e118bec28e324c05eeea4a274b7f5d5e',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'test-context',
            '7f22a943efd3537ef9e0dc98e7031d9f',
            '9c2182653d63d369cecc7bf96e24325aaa09eaca943accd53b263ad8390eb4e39b36ad4a9e89b2849cd7699138f14b825722073729eebae8a49f8e9ad278a367',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'test-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a4',
            'f3485c8fec6e20d0e81a332d9a6e7293985ad345076a2b167d3b682e612ab549',
        ];
    }

    protected function createKdfInstance(?string $hashAlgo = null, string|Stringable $hashStaticSalt = ''): KdfInterface
    {
        return $hashAlgo
            ? new KdfPasswordArgon2(hashAlgo: $hashAlgo, hashStaticSalt: $hashStaticSalt)
            : new KdfPasswordArgon2(hashStaticSalt: $hashStaticSalt);
    }
}
