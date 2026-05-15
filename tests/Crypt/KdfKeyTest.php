<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\KdfInterface;
use Yiisoft\Security\Crypt\Kdf\KdfKey;

final class KdfKeyTest extends AbstractKdfCase
{
    protected function createKdfInstance(?string $hash = null): KdfInterface
    {
        return $hash ? new KdfKey($hash) : new KdfKey();
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
            'de32d3e43275d27b1069f1046f879d7c9973d5c56c4b0844958ffb5fdd37a610',
        ];
        yield [
            'sha512',
            '84c7e9fb214e1d5d3ac6d9ae7b7af33f23355f4795831dcdb5d97093ec42d3d32b4391c7e1b2673ec5577aad934d231d24fd9e5032dd845e86e75a965eba4207',
            64,
            'text-context',
            '7f22a943efd3537ef9e0dc98e7031d9f71b16868ccc0aafe110ab32f7e54db613b58b5663c14b703b019278cc80dc615f60df1c6a4cc88f1b207a72783be7d44',
            '1d87ec9ba105409270c0232613a27858e2ff86745dcc1f9f4cfb04854bd6be8c581a3570857b1910578b4c5f03c7653985940a3800e2915125a7a1eda609079d',
        ];
        yield [
            'sha3-256',
            '983447213c2c295a72a64d95e069793b9acf4cbaef59b71a86cbc6aec4f020e4',
            32,
            'text-context',
            'aa24ea6b979b1a857d9f9dfa0dcac8a44c3f7b9ea061551529556ac70dd0cfeb',
            'f363aa6f06ccba2c1cf98f96c25f03861275c7060229187b398b12683e168452',
        ];
    }

    public function testInvalidSecretThrowsException(): void
    {
        $kdf = $this->createKdfInstance();

        $this->expectException(EncryptionException::class);
        $kdf->createKey('', 32, 'test-context', 'test-salt');
    }
}
