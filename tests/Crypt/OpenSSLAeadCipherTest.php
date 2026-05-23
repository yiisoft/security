<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use Yiisoft\Security\Crypt\AeadCipherInterface;
use Yiisoft\Security\Crypt\Cipher\OpenSSLAeadCipher;

final class OpenSSLAeadCipherTest extends AbstractAeadCipherCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL extension is required for these tests.');
        }
    }

    protected function createCipherInstance(?string $cipher = null): AeadCipherInterface
    {
        return $cipher ? new OpenSSLAeadCipher($cipher) : new OpenSSLAeadCipher();
    }

    public static function dataProviderCiphers(): iterable
    {
        yield ['AES-128-GCM'];
        yield ['AES-192-GCM'];
        yield ['AES-256-GCM'];
    }

    public static function dataProviderEncrypted(): iterable
    {
        yield [
            'AES-128-GCM',
            '54c4cc0f038dc65dfaaebef3cecbfcec',
            '553defeffbe4e315bf9816f6',
            'test-plain-data',
            '4b87ea2f31b25f503a44a3ffb1e2b47597d0671d7077163bd126757d7aa0af',
        ];
        yield [
            'AES-192-GCM',
            '9757543de0cce63fb868f4da1aef19cbc4277e867b2eb862',
            '0d14ea15adb2c3cee018a858',
            'test-plain-data',
            '8cca6a6348f688b64f8ea62187b9de55ecb9f4dd0199d0bd39e428d72a4b3f',
        ];
        yield [
            'AES-256-GCM',
            '647a582c7c0ef535b88dcaa8671effb413228d8eef72c8d111029c4825aca7d6',
            '3437af16a83c0284b449a4a4',
            'test-plain-data',
            '7c5fd62f60ad234d9dbf8efd26252a71b273b66b5e9fa89d27c519aac6bb54',
        ];
    }
}
