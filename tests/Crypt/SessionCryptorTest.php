<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\Crypt\CipherInterface;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\KdfInterface;
use Yiisoft\Security\Crypt\SessionCryptor;
use Yiisoft\Strings\StringHelper;

final class SessionCryptorTest extends TestCase
{
    private const KEY_SIZE = 32;
    private const NONCE_SIZE = 12;

    public function testEncryptProducesExpectedStructure(): void
    {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        [$cipher, $kdf] = $this->createMocks();

        $kdf->expects($this->once())
            ->method('createKey')
            ->with($secret, self::KEY_SIZE, $context, $this->callback(static fn($salt) => StringHelper::byteLength($salt) === self::KEY_SIZE))
            ->willReturn('test-derivedkey-123456');

        $cipher->expects($this->once())
            ->method('encrypt')
            ->with($plaintext, 'test-derivedkey-123456', $this->callback(static fn($nonce) => StringHelper::byteLength($nonce) === self::NONCE_SIZE))
            ->willReturn('test-ciphertext-and-tag');

        $cryptor = new SessionCryptor($cipher, $kdf);
        $result = $cryptor->encrypt($plaintext, $secret, $context);

        // result structure: keySalt || nonce || ciphertext
        $this->assertIsString($result);
        $this->assertEquals(
                self::KEY_SIZE + self::NONCE_SIZE + StringHelper::byteLength('test-ciphertext-and-tag'),
                StringHelper::byteLength($result)
        );

        $keySalt = StringHelper::byteSubstring($result, 0, self::KEY_SIZE);
        $nonce = StringHelper::byteSubstring($result, self::KEY_SIZE, self::NONCE_SIZE);
        $ciphertext = StringHelper::byteSubstring($result, self::KEY_SIZE + self::NONCE_SIZE);

        $this->assertEquals(self::KEY_SIZE, StringHelper::byteLength($keySalt));
        $this->assertEquals(self::NONCE_SIZE, StringHelper::byteLength($nonce));
        $this->assertEquals('test-ciphertext-and-tag', $ciphertext);
    }

    public function testDecryptReturnsPlaintextAndUsesKdfAndCipher(): void
    {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        $keySalt = str_repeat("\x01", self::KEY_SIZE);
        $nonce = str_repeat("\x02", self::NONCE_SIZE);

        $encryptedPayload = 'encrypted-by-cipher';
        
        [$cipher, $kdf] = $this->createMocks();

        $kdf->expects($this->once())
            ->method('createKey')
            ->with($secret, self::KEY_SIZE, $context, $keySalt)
            ->willReturn('dek');

        $cipher->expects($this->once())
            ->method('decrypt')
            ->with($encryptedPayload, 'dek', $nonce)
            ->willReturn($plaintext);

        // Build the encrypted blob: keySalt || nonce || encryptedPayload
        $blob = $keySalt . $nonce . $encryptedPayload;
        $cryptor = new SessionCryptor($cipher, $kdf);
        $decrypted = $cryptor->decrypt($blob, $secret, $context);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptionIsRandomized(): void
    {
        [$cipher, $kdf] = $this->createMocks();

        $kdf->method('createKey')->willReturn('dek');
        $cipher->method('encrypt')->willReturn('cipher');

        $cryptor = new SessionCryptor($cipher, $kdf);

        $res1 = $cryptor->encrypt('data', 'secret');
        $res2 = $cryptor->encrypt('data', 'secret');

        $this->assertNotSame($res1, $res2);
    }

    public function testDecryptThrowsWhenDataTooShort(): void
    {
        [$cipher, $kdf] = $this->createMocks();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Encrypted data is too short.');

        $cryptor = new SessionCryptor($cipher, $kdf);
        $cryptor->decrypt('short', 'secret');
    }

    private function createMocks(): array
    {
        $kdf = $this->createMock(KdfInterface::class);

        $cipher = $this->createMock(CipherInterface::class);
        $cipher->method('getKeySize')->willReturn(self::KEY_SIZE);
        $cipher->method('getNonceSize')->willReturn(self::NONCE_SIZE);

        return [$cipher, $kdf];
    }
    
}
