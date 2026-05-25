<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use Yiisoft\Security\Crypt\KdfInterface;
use Yiisoft\Security\Crypt\Kdf\KdfPasswordArgon2;

final class KdfPasswordArgon2Test extends AbstractKdfCase
{
    protected function createKdfInstance(?string $hash = null): KdfInterface
    {
        return $hash ? new KdfPasswordArgon2($hash) : new KdfPasswordArgon2();
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
            'ae8cbb001c062cd2c00ed6956842dc4d',
            '97d9d6eb9b8b88eac18274b75c73b439cd099b4e778f290bcc156038e8f40e50',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'text-context',
            '7f22a943efd3537ef9e0dc98e7031d9f',
            'abcd5a66003c25a8ff8190716c976825941265a50de8bef39d6f8c56d9b7bdd1cabf61ea1079eb38ba395986e3eba2605a888cc7c4433b5218624d95bdfcf0a7',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'text-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a4',
            '4f097ff97d2faeb2ce0b99c29148e60929bbbea6ba3c442d5807a645a933b3b6',
        ];
    }
}
