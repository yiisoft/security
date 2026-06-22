<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Cipher;

use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Security\Crypto\Cipher\OpenSSLWrapCipher;

use function extension_loaded;

final class OpenSSLWrapCipherTest extends AbstractCipherCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL extension is required for these tests.');
        }
    }

    public static function dataProviderCiphers(): iterable
    {
        yield ['AES-128-WRAP'];
        yield ['AES-192-WRAP'];
        yield ['AES-256-WRAP'];
    }

    public static function dataProviderEncrypted(): iterable
    {
        yield [
            'AES-128-WRAP',
            '54c4cc0f038dc65dfaaebef3cecbfcec',
            '',
            '',
            '',
        ];
        yield [
            'AES-128-WRAP',
            '54c4cc0f038dc65dfaaebef3cecbfcec',
            '',
            'test-plain-data-',
            'f5e0073e78eb2621fab4f6b58eb184b8cff4fa1d1ef4b6b9',
        ];
        yield [
            'AES-192-WRAP',
            '9757543de0cce63fb868f4da1aef19cbc4277e867b2eb862',
            '',
            'test-plain-data-',
            '54bb69969c91d6163ef463989d932f0c492674abef0873f2',
        ];
        yield [
            'AES-256-WRAP',
            '647a582c7c0ef535b88dcaa8671effb413228d8eef72c8d111029c4825aca7d6',
            '',
            'test-plain-data-',
            'c08c23d569b502cb4b98dd4ac8672e0487f8e3d5e490f790',
        ];
    }

    public function testNonceIsIgnored(): void
    {
        $cipher = $this->createCipherInstance();
        $key = random_bytes($cipher->getKeySize());
        $plaintext = $this->getPlainText();
        $nonce1 = random_bytes(8); // размер не важен
        $nonce2 = random_bytes(8);

        $ciphertext1 = $cipher->encrypt($plaintext, $key, $nonce1);
        $ciphertext2 = $cipher->encrypt($plaintext, $key, $nonce2);
        $this->assertSame($ciphertext1, $ciphertext2);
    }

    protected function createCipherInstance(?string $cipher = null): CipherInterface
    {
        return $cipher ? new OpenSSLWrapCipher($cipher) : new OpenSSLWrapCipher();
    }

    protected static function getPlainText(): string
    {
        return 'test-plain-data-';
    }
}
