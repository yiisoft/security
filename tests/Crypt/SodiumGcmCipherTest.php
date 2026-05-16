<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use Yiisoft\Security\Crypt\CipherInterface;
use Yiisoft\Security\Crypt\Cipher\SodiumAeadCipher;

final class SodiumGcmCipherTest extends AbstractAeadCipherCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium extension is required for these tests.');
        } elseif (!sodium_crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('Sodium AES-256-GCM requires hardware that supports hardware-accelerated AES.');
        }
    }

    protected function createCipherInstance(?string $cipher = null): CipherInterface
    {
        return $cipher ? new SodiumAeadCipher($cipher) : new SodiumAeadCipher();
    }

    public static function dataProviderCiphers(): iterable
    {
        yield ['AES-256-GCM'];
    }

    public static function dataProviderEncrypted(): iterable
    {
        yield [
            'AES-256-GCM',
            'd2000811111ba11ba7a2497911c43111a00b433d8437b3538d57d75366b32bb2',
            '429895de6466a4622f287f0c',
            'test-plain-data',
            'ae9cf157604ed2a9fd7ad971d005c4e571ec8a6e697e000414e5820748912c',
        ];
    }
}
