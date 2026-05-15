<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use Yiisoft\Security\Crypt\KdfInterface;
use Yiisoft\Security\Crypt\Kdf\KdfPassword;

final class KdfPasswordTest extends AbstractKdfCase
{
    protected function createKdfInstance(?string $hash = null): KdfInterface
    {
        return $hash ? new KdfPassword($hash, 100_000) : new KdfPassword(iterations: 100_000);
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
            '91718343d3673e2c2407ef6f79d3516a4e111ce56c935cd1ec9566b16b21b16b',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'text-context',
            '7f22a943efd3537ef9e0dc98e7031d9f71b16868ccc0aafe110ab32f7e54db613b58b5663c14b703b019278cc80dc615f60df1c6a4cc88f1b207a72783be7d44',
            'c377ad8ff1c4438f862e43ee5ef5431f928fd64890d9ed3ba401d91c37e5aee5a7d90ef09f3ad4ea82506b32c9950bebfd4820895667b8c478d3f4e57e8ebff4',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'text-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a44c3f7b9ea061551529556ac70dd0cfeb',
            '07f140674180f0ba9d4c6dea90a0ad389274624bc966c550519c98704f1df504',
        ];
    }
}
