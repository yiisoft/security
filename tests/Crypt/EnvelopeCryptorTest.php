<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\Crypt\AeadCipherInterface;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\KdfInterface;
use Yiisoft\Security\Crypt\EnvelopeCryptor;
use Yiisoft\Strings\StringHelper;

final class EnvelopeCryptorTest extends TestCase
{
    private const KEY_SIZE = 32;
    private const NONCE_SIZE = 12;
    private const TAG_SIZE = 16;
    private const SALT_SIZE = 16;

    public function testEncryptProducesExpectedStructure(): void
    {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        $kek = random_bytes(self::KEY_SIZE);

        [$cipher, $kdf] = $this->createMocks();

        $kdf->expects($this->once())
            ->method('createKey')
            ->with($secret, self::KEY_SIZE, $context, $this->callback(static fn($salt) => StringHelper::byteLength($salt) === self::SALT_SIZE))
            ->willReturn($kek);

        $cipher->expects($this->exactly(2))
            ->method('encrypt')
            ->willReturnCallback(function (...$args) use ($plaintext, $kek) {
                static $callCount = 0;
                $callCount++;

                if ($callCount === 1) {
                    // First call: payload = dek, key = kek, nonce length = nonceSize
                    [$payload, $key, $nonce] = $args;
                    $this->assertIsString($payload);
                    $this->assertEquals(self::KEY_SIZE, StringHelper::byteLength($payload));
                    $this->assertEquals($kek, $key);
                    $this->assertEquals(self::NONCE_SIZE, StringHelper::byteLength($nonce));

                    return 'encDek--------------------------' . '________________';
                }

                [$payload, $key, $nonce] = $args;
                $this->assertEquals($plaintext, $payload);
                $this->assertEquals(self::KEY_SIZE, StringHelper::byteLength($key));
                $this->assertEquals(self::NONCE_SIZE, StringHelper::byteLength($nonce));

                return 'encData';
            });

        $cryptor = new EnvelopeCryptor($cipher, $kdf);

        $result = $cryptor->encrypt($plaintext, $secret, $context);
        $this->assertIsString($result);
        $this->assertEquals(
            self::SALT_SIZE + self::NONCE_SIZE + (self::KEY_SIZE + self::TAG_SIZE) + self::NONCE_SIZE + StringHelper::byteLength('encData'),
            StringHelper::byteLength($result)
        );

        $keySalt = StringHelper::byteSubstring($result, 0, self::SALT_SIZE);
        $dekNonce = StringHelper::byteSubstring($result, self::SALT_SIZE, self::NONCE_SIZE);
        $encDek = StringHelper::byteSubstring($result, self::SALT_SIZE + self::NONCE_SIZE, self::KEY_SIZE + self::TAG_SIZE);
        $dataNonce = StringHelper::byteSubstring($result, self::SALT_SIZE + self::NONCE_SIZE + (self::KEY_SIZE + self::TAG_SIZE), self::NONCE_SIZE);
        $ciphertext = StringHelper::byteSubstring($result, self::SALT_SIZE + self::NONCE_SIZE + (self::KEY_SIZE + self::TAG_SIZE) + self::NONCE_SIZE);

        $this->assertEquals(self::SALT_SIZE, StringHelper::byteLength($keySalt));
        $this->assertEquals(self::NONCE_SIZE, StringHelper::byteLength($dekNonce));
        $this->assertEquals(self::NONCE_SIZE, StringHelper::byteLength($dataNonce));
        $this->assertEquals('encDek--------------------------' . '________________', $encDek);
        $this->assertEquals('encData', $ciphertext);
    }

    public function testDecryptReturnsPlaintextAndUsesKdfAndCipher(): void
    {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        $keySalt = str_repeat("\x01", self::SALT_SIZE);
        $dekNonce = str_repeat("\x02", self::NONCE_SIZE);
        $dek = str_repeat("\x10", self::KEY_SIZE);
        $dataNonce = str_repeat("\x20", self::NONCE_SIZE);
        $tag = str_repeat("\x30", self::TAG_SIZE);

        $encDekWithTag = $dek . $tag;
        $encDataWithTag = $plaintext . $tag;

        [$cipher, $kdf] = $this->createMocks();

        $kdf->expects($this->once())
            ->method('createKey')
            ->with($secret, self::KEY_SIZE, $context, $keySalt)
            ->willReturn('kek');

        $cipher->expects($this->exactly(2))
            ->method('decrypt')
            ->willReturnCallback(function (...$args) use ($plaintext, $encDekWithTag, $encDataWithTag, $dekNonce, $dek, $dataNonce) {
                static $callCount = 0;
                $callCount++;

                if ($callCount === 1) {
                    [$payload, $key, $nonce] = $args;
                    $this->assertEquals($encDekWithTag, $payload);
                    $this->assertEquals('kek', $key);
                    $this->assertEquals($dekNonce, $nonce);

                    return $dek;
                }

                [$payload, $key, $nonce] = $args;
                $this->assertEquals($encDataWithTag, $payload);
                $this->assertEquals($dek, $key);
                $this->assertEquals($dataNonce, $nonce);

                return $plaintext;
            });

        $blob = $keySalt . $dekNonce . $encDekWithTag . $dataNonce . $encDataWithTag;
        $cryptor = new EnvelopeCryptor($cipher, $kdf);
        $decrypted = $cryptor->decrypt($blob, $secret, $context);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptionIsRandomized(): void
    {
        [$cipher, $kdf] = $this->createMocks();

        $kdf->method('createKey')->willReturn('dek');
        $cipher->method('encrypt')->willReturn('cipher');

        $cryptor = new EnvelopeCryptor($cipher, $kdf);

        $res1 = $cryptor->encrypt('data', 'secret');
        $res2 = $cryptor->encrypt('data', 'secret');

        $this->assertNotSame($res1, $res2);
    }

    public function testDecryptThrowsWhenDataTooShort(): void
    {
        [$cipher, $kdf] = $this->createMocks();

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Encrypted data is too short.');

        $cryptor = new EnvelopeCryptor($cipher, $kdf);
        $cryptor->decrypt('short', 'secret');
    }

    private function createMocks(): array
    {
        $kdf = $this->createMock(KdfInterface::class);
        $kdf->method('getSaltSize')->willReturn(self::SALT_SIZE);

        $cipher = $this->createMock(AeadCipherInterface::class);
        $cipher->method('getKeySize')->willReturn(self::KEY_SIZE);
        $cipher->method('getNonceSize')->willReturn(self::NONCE_SIZE);
        $cipher->method('getTagSize')->willReturn(self::TAG_SIZE);

        return [$cipher, $kdf];
    }
}
