<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Cipher;

use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Security\Crypto\Cipher\SodiumAeadCipher;

final class SodiumAeadCipherTest extends AbstractCipherCase
{
    use CipherWithNonceTrait;
    use CipherWithAeadTrait;

    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is required for these tests.');
        }
    }

    protected function createCipherInstance(?string $cipher = null): CipherInterface
    {
        return $cipher ? new SodiumAeadCipher($cipher) : new SodiumAeadCipher();
    }

    protected static function getPlainText(): string
    {
        return 'test-plain-data';
    }

    public static function dataProviderCiphers(): iterable
    {
        yield ['CHACHA20-POLY1305-IETF'];
        yield ['XCHACHA20-POLY1305-IETF'];
    }

    public static function dataProviderEncrypted(): iterable
    {
        yield [
            'CHACHA20-POLY1305-IETF',
            'adcc610fd179117c7b383b9c9e4c2b106fc72f98290c095452a07b0ad5ed5767',
            '353bf3e8a440ddd5b125b8df',
            '',
            '3584c3be670fa3a6d6ffc332beaf2302',
        ];
        yield [
            'CHACHA20-POLY1305-IETF',
            'adcc610fd179117c7b383b9c9e4c2b106fc72f98290c095452a07b0ad5ed5767',
            '353bf3e8a440ddd5b125b8df',
            'test-plain-data',
            '75058e089d84a58fed82a822b462b2a3dcdf5b5b4cda445fdba26ccd012503',
        ];
        yield [
            'XCHACHA20-POLY1305-IETF',
            '89fe0c0b2c9b74cdb87d13f0b9f835bde84a3f0c4940c026c5d888db254271f0',
            'fc6f945727c02ac590d53cc17c2f144949526a4f2d2fef41',
            'test-plain-data',
            '4c88400da53f878bf9de7749a70b38022ce8166effecc64b8c8a49c2c0f28c',
        ];
    }
}
