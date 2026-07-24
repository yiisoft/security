<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Security\Crypto\KdfCryptor;
use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Strings\StringHelper;

final class KdfCryptorTest extends TestCase
{
    #[DataProvider('dataProviderConfigs')]
    public function testEncryptProducesExpectedStructure(
        int $kdfSaltSize,
        int $keySize,
        int $nonceSize,
    ): void {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        [$kdf, $cipher] = $this->createMocks(
            $kdfSaltSize,
            $keySize,
            $nonceSize,
        );

        $kdf->expects($this->once())
            ->method('derive')
            ->with($secret, $keySize, $context, $this->callback(static fn($salt) => StringHelper::byteLength($salt) === $kdfSaltSize))
            ->willReturn('test-derivedkey-123456');

        $cipher->expects($this->once())
            ->method('encrypt')
            ->with($plaintext, 'test-derivedkey-123456', $this->callback(static fn($nonce) => StringHelper::byteLength($nonce) === $nonceSize))
            ->willReturn('test-ciphertext-and-tag');

        $cryptor = new KdfCryptor(kdf: $kdf, cipher: $cipher);
        $result = $cryptor->encrypt($plaintext, $secret, $context);

        // result structure: keySalt || nonce || ciphertext
        $this->assertIsString($result);
        $this->assertSame(
            $kdfSaltSize + $nonceSize + StringHelper::byteLength('test-ciphertext-and-tag'),
            StringHelper::byteLength($result),
        );

        $keySalt = StringHelper::byteSubstring($result, 0, $kdfSaltSize);
        $nonce = StringHelper::byteSubstring($result, $kdfSaltSize, $nonceSize);
        $ciphertext = StringHelper::byteSubstring($result, $kdfSaltSize + $nonceSize);

        $this->assertSame($kdfSaltSize, StringHelper::byteLength($keySalt));
        $this->assertSame($nonceSize, StringHelper::byteLength($nonce));
        $this->assertSame('test-ciphertext-and-tag', $ciphertext);
    }

    #[DataProvider('dataProviderConfigs')]
    public function testDecryptReturnsPlaintextAndUsesKdfAndCipher(
        int $kdfSaltSize,
        int $keySize,
        int $nonceSize,
    ): void {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        $keySalt = str_repeat("\x01", $kdfSaltSize);
        $nonce = str_repeat("\x02", $nonceSize);

        $encryptedPayload = 'encrypted-by-cipher';

        [$kdf, $cipher] = $this->createMocks(
            $kdfSaltSize,
            $keySize,
            $nonceSize,
        );

        $kdf->expects($this->once())
            ->method('derive')
            ->with($secret, $keySize, $context, $keySalt)
            ->willReturn('dek');

        $cipher->expects($this->once())
            ->method('decrypt')
            ->with($encryptedPayload, 'dek', $nonce)
            ->willReturn($plaintext);

        // Build the encrypted blob: keySalt || nonce || encryptedPayload
        $blob = $keySalt . $nonce . $encryptedPayload;
        $cryptor = new KdfCryptor(kdf: $kdf, cipher: $cipher);
        $decrypted = $cryptor->decrypt($blob, $secret, $context);
        $this->assertSame($plaintext, $decrypted);
    }

    #[DataProvider('dataProviderConfigs')]
    public function testEncryptionIsRandomized(
        int $kdfSaltSize,
        int $keySize,
        int $nonceSize,
    ): void {
        [$kdf, $cipher] = $this->createMocks(
            $kdfSaltSize,
            $keySize,
            $nonceSize,
        );

        $kdf->method('derive')->willReturn('dek');
        $cipher->method('encrypt')->willReturn('encrypted_data');

        $cryptor = new KdfCryptor(kdf: $kdf, cipher: $cipher);

        $res1 = $cryptor->encrypt('data', 'secret');
        $res2 = $cryptor->encrypt('data', 'secret');

        // If at least one random component (salt or nonce) exists, the results must differ.
        if ($kdfSaltSize > 0 || $nonceSize > 0) {
            $this->assertNotSame($res1, $res2, 'Results must differ when salt or nonce is present.');
        } else {
            $this->assertSame($res1, $res2);
        }

        // Verify that KDF salt is random when its size > 0
        if ($kdfSaltSize > 0) {
            $salt1 = StringHelper::byteSubstring($res1, 0, $kdfSaltSize);
            $salt2 = StringHelper::byteSubstring($res2, 0, $kdfSaltSize);
            $this->assertNotSame($salt1, $salt2, 'KDF salt must be different for each encryption');
        }

        // Verify that data nonce is random when its size > 0
        if ($nonceSize > 0) {
            $nonce1 = StringHelper::byteSubstring($res1, $kdfSaltSize, $nonceSize);
            $nonce2 = StringHelper::byteSubstring($res2, $kdfSaltSize, $nonceSize);
            $this->assertNotSame($nonce1, $nonce2, 'Data nonce must be different for each encryption');
        }
    }

    public function testDecryptThrowsWhenDataTooShort(): void
    {
        [$kdf, $cipher] = $this->createMocks(...[
            'kdfSaltSize' => 16,
            'keySize' => 32,
            'nonceSize' => 12,
        ]);

        $cipher->method('encrypt')->willReturn('encrypted_data');

        $this->expectException(EncryptionException::class);

        $cryptor = new KdfCryptor(kdf: $kdf, cipher: $cipher);
        $cryptor->decrypt('short', 'secret');
    }

    /**
     * [kdfSaltSize, kwKeySize, kwNonceSize, kwOverheadSize, dataKeySize, dataNonceSize, dataOverheadSize]
     */
    public static function dataProviderConfigs(): iterable
    {
        yield [
            'kdfSaltSize' => 16,
            'keySize' => 32,
            'nonceSize' => 12,
        ];
        // data ciper without nonce
        yield [
            'kdfSaltSize' => 16,
            'keySize' => 32,
            'nonceSize' => 0,
        ];
        // kdf without salt
        yield [
            'kdfSaltSize' => 0,
            'keySize' => 32,
            'nonceSize' => 12,
        ];
        // kdf without salt, kw ciper without nonce
        yield [
            'kdfSaltSize' => 0,
            'keySize' => 32,
            'nonceSize' => 0,
        ];
    }

    private function createMocks(
        int $kdfSaltSize,
        int $keySize,
        int $nonceSize,
    ): array {
        $kdf = $this->createMock(KdfInterface::class);
        $kdf->method('getSaltSize')->willReturn($kdfSaltSize);

        $cipher = $this->createMock(CipherInterface::class);
        $cipher->method('getKeySize')->willReturn($keySize);
        $cipher->method('getNonceSize')->willReturn($nonceSize);

        return [$kdf, $cipher];
    }
}
