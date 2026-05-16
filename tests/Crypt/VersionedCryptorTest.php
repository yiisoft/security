<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use Yiisoft\Security\Crypt\CryptorInterface;
use Yiisoft\Security\Crypt\EncryptionException;
use Yiisoft\Security\Crypt\VersionedCryptor;

final class VersionedCryptorTest extends TestCase
{
    public function  testEncryptPrependsVersionAndDelegates(): void
    {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';
        $v = 'v1';

        $cryptor = $this->createMock(CryptorInterface::class);
        $cryptor->expects($this->once())
            ->method('encrypt')
            ->with($plaintext, $secret, $context)
            ->willReturn('encrypted-payload');

        $versioned = new VersionedCryptor([$v => $cryptor], $v, 2);
        $result = $versioned->encrypt($plaintext, $secret, $context);

        $this->assertSame($v . 'encrypted-payload', $result);
    }

    public function testDecryptExtractsVersionAndCallsCorrectCryptor(): void
    {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        $encryptedPayload = 'encrypted-part';
        $fullData = 'v2' . $encryptedPayload;

        $cryptorV2 = $this->createMock(CryptorInterface::class);
        $cryptorV2->expects($this->once())
            ->method('decrypt')
            ->with($encryptedPayload, $secret, $context)
            ->willReturn($plaintext);

        $versioned = new VersionedCryptor(['v2' => $cryptorV2], 'v2', 2);
        $result = $versioned->decrypt($fullData, $secret, $context);

        $this->assertSame($plaintext, $result);
    }

    public function testEncryptDecryptDifferentVersions(): void
    {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';

        $cryptorV1 = $this->createMock(CryptorInterface::class);
        $cryptorV1->method('encrypt')->willReturn('encrypted_data_v1');
        $cryptorV1->method('decrypt')->willReturn($plaintext);

        $cryptorV2 = $this->createMock(CryptorInterface::class);
        $cryptorV2->method('encrypt')->willReturn('encrypted_data_v2');
        $cryptorV2->method('decrypt')->willReturn($plaintext);

        $versionedCryptor = new VersionedCryptor([
            'v1' => $cryptorV1,
            'v2' => $cryptorV2,
        ], 'v2', 2);

        $encryptedDataV1 = 'v1' . $cryptorV1->encrypt($plaintext, $secret);
        $encryptedDataV2 = 'v2' . $cryptorV2->encrypt($plaintext, $secret);

        $decryptedDataV1 = $versionedCryptor->decrypt($encryptedDataV1, $secret);
        $decryptedDataV2 = $versionedCryptor->decrypt($encryptedDataV2, $secret);

        $this->assertEquals($plaintext, $decryptedDataV1);
        $this->assertEquals($plaintext, $decryptedDataV2);
    }

    public function testContextPassedToUnderlyingCryptor(): void
    {
        $secret = 'test-secret';
        $context = 'test-context';

        $cryptor = $this->createMock(CryptorInterface::class);
        $cryptor->expects($this->once())
            ->method('encrypt')
            ->with('data', $secret, $context)
            ->willReturn('encrypted');

        $cryptor->expects($this->once())
            ->method('decrypt')
            ->with('encrypted', $secret, $context)
            ->willReturn('data');

        $versioned = new VersionedCryptor(['v1' => $cryptor], 'v1', 2);

        $encrypted = $versioned->encrypt('data', $secret, $context);
        $decrypted = $versioned->decrypt($encrypted, $secret, $context);

        $this->assertSame('data', $decrypted);
    }

    public function testIntegerKeyIsNormalizedToStringAndLengthChecked(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor([12 => $this->createMock(CryptorInterface::class)], '123', 3);
    }

    public function testDecryptThrowsExceptionWhenVersionNotFound(): void
    {
        $versionedCryptor = new VersionedCryptor(['v1' => $this->createMock(CryptorInterface::class)], 'v1', 2);

        $this->expectException(RuntimeException::class);
        $versionedCryptor->decrypt('v2' . 'test-plain-data', 'test-secret');
    }

    public function testConstructThrowsWhenCurrentVersionNotRegistered(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(['v1' => $this->createMock(CryptorInterface::class)], 'v2', 2);
    }

    public function testConstructorValidationThrows(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor([], 'v1', 2);
    }

    public function testConstructorThrowsExceptionWhenCryptorNotInstanceOfInterface(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(['v1' => new \stdClass()], 'v1', 2);
    }

    public function testConstructorThrowsExceptionWhenVersionSizeLessThanOne(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(['v1' => $this->createMock(CryptorInterface::class)], 'v1', 0);
    }

    public function testConstructorThrowsExceptionWhenVersionLengthMismatch(): void
    {
        $this->expectException(RuntimeException::class);
        new VersionedCryptor(['v1' => $this->createMock(CryptorInterface::class)], 'v1', 3);
    }

    public function testDecryptThrowsExceptionWhenDataTooShort(): void
    {
        $cryptor = $this->createMock(CryptorInterface::class);
        $versionedCryptor = new VersionedCryptor(['v1' => $cryptor], 'v1', 2);

        $this->expectException(EncryptionException::class);
        $versionedCryptor->decrypt('x', 'secret');
    }

    public function testDecryptInvalidData(): void
    {
        $cryptor = $this->createMock(CryptorInterface::class);
        $cryptor->method('decrypt')->willThrowException(new EncryptionException());

        $versionedCryptor = new VersionedCryptor(['v1' => $cryptor], 'v1', 2);

        $this->expectException(EncryptionException::class);
        $versionedCryptor->decrypt('v1' . 'test-plain-data', 'test-secret');
    }
}
