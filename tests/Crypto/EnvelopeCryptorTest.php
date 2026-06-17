<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Yiisoft\Security\Crypto\EncryptionException;
use Yiisoft\Security\Crypto\EnvelopeCryptor;
use Yiisoft\Security\Crypto\KdfInterface;
use Yiisoft\Security\Crypto\CipherInterface;
use Yiisoft\Strings\StringHelper;

final class EnvelopeCryptorTest extends TestCase
{
    #[DataProvider('dataProviderConfigs')]
    public function testEncryptProducesExpectedStructure(
        int $kdfSaltSize,
        int $dataKeySize,
        int $dataNonceSize,
        int $dataOverheadSize,
        int $kwKeySize,
        int $kwNonceSize,
        int $kwOverheadSize,
    ): void {
        $plaintext = 'test-plain-data';
        $cyphertext = 'testcypherdata';
        $secret = 'test-secret';
        $context = 'test-context';
        $wrappedDek = str_repeat('x', $dataKeySize);

        [$kdf, $cipher, $kwCipher] = $this->createMocks(
            $kdfSaltSize,
            $dataKeySize,
            $dataNonceSize,
            $dataOverheadSize,
            $kwKeySize,
            $kwNonceSize,
            $kwOverheadSize,
        );

        $kek = random_bytes($kwKeySize);

        $kdf->expects($this->once())
            ->method('derive')
            ->with($secret, $kwKeySize, $context, $this->callback(static fn($salt) => StringHelper::byteLength($salt) === $kdfSaltSize))
            ->willReturn($kek);

        // Expect cipher->encrypt() for data
        $cipher->expects($this->once())
            ->method('encrypt')
            ->with($plaintext, $this->callback(static fn($dek) => StringHelper::byteLength($dek) === $dataKeySize), $this->callback(static fn($nonce) => StringHelper::byteLength($nonce) === $dataNonceSize))
            ->willReturn($cyphertext . str_repeat('t', $dataOverheadSize));

        // Expect kwCipher->encrypt() for DEK wrapping
        $kwCipher->expects($this->once())
            ->method('encrypt')
            ->willReturnCallback(function ($dek, $key, $nonce) use ($kek, $kwNonceSize, $kwOverheadSize, $dataKeySize, $wrappedDek) {
                $this->assertSame($dataKeySize, StringHelper::byteLength($dek));
                $this->assertSame($kek, $key);
                $this->assertSame($kwNonceSize, StringHelper::byteLength($nonce));
                return $wrappedDek . str_repeat('t', $kwOverheadSize);
            });

        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher, kwCipher: $kwCipher);
        $result = $cryptor->encrypt($plaintext, $secret, $context);

        // Check overall length: salt + dekNonce + wrappedDEK + dataNonce + encryptedData
        $expectedLength = $kdfSaltSize
            + $kwNonceSize
            + ($dataKeySize + $kwOverheadSize)
            + $dataNonceSize
            + (StringHelper::byteLength($cyphertext) + $dataOverheadSize);

        $this->assertSame($expectedLength, StringHelper::byteLength($result));

        // Parse components
        $offset = 0;
        $salt = StringHelper::byteSubstring($result, $offset, $kdfSaltSize);
        $offset += $kdfSaltSize;
        $dekNonce = StringHelper::byteSubstring($result, $offset, $kwNonceSize);
        $offset += $kwNonceSize;
        $parsedWrappedDek = StringHelper::byteSubstring($result, $offset, $dataKeySize + $kwOverheadSize);
        $offset += $dataKeySize + $kwOverheadSize;
        $dataNonce = StringHelper::byteSubstring($result, $offset, $dataNonceSize);
        $offset += $dataNonceSize;
        $encryptedData = StringHelper::byteSubstring($result, $offset);

        $this->assertSame($kdfSaltSize, StringHelper::byteLength($salt));
        $this->assertSame($kwNonceSize, StringHelper::byteLength($dekNonce));
        $this->assertSame($dataNonceSize, StringHelper::byteLength($dataNonce));
        $this->assertSame($wrappedDek . str_repeat('t', $kwOverheadSize), $parsedWrappedDek);
        $this->assertSame($cyphertext . str_repeat('t', $dataOverheadSize), $encryptedData);
    }

    #[DataProvider('dataProviderConfigs')]
    public function testDecryptReturnsPlaintextAndUsesKdfAndCiphers(
        int $kdfSaltSize,
        int $dataKeySize,
        int $dataNonceSize,
        int $dataOverheadSize,
        int $kwKeySize,
        int $kwNonceSize,
        int $kwOverheadSize,
    ): void {
        $plaintext = 'test-plain-data';
        $secret = 'test-secret';
        $context = 'test-context';

        $salt = str_repeat("\x01", $kdfSaltSize);
        $dekNonce = str_repeat("\x02", $kwNonceSize);
        $dataNonce = str_repeat("\x03", $dataNonceSize);
        $dek = str_repeat("\x10", $dataKeySize);
        $wrappedDek = $dek . str_repeat("\x20", $kwOverheadSize);
        $encryptedData = $plaintext . str_repeat("\x30", $dataOverheadSize);

        $blob = $salt . $dekNonce . $wrappedDek . $dataNonce . $encryptedData;

        [$kdf, $cipher, $kwCipher] = $this->createMocks(
            $kdfSaltSize,
            $dataKeySize,
            $dataNonceSize,
            $dataOverheadSize,
            $kwKeySize,
            $kwNonceSize,
            $kwOverheadSize,
        );

        $kdf->expects($this->once())
            ->method('derive')
            ->with($secret, $kwKeySize, $context, $salt)
            ->willReturn('kek');

        $cipher->expects($this->once())
            ->method('decrypt')
            ->with($encryptedData, $dek, $dataNonce)
            ->willReturn($plaintext);

        $kwCipher->expects($this->once())
            ->method('decrypt')
            ->with($wrappedDek, 'kek', $dekNonce)
            ->willReturn($dek);

        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher, kwCipher: $kwCipher);
        $decrypted = $cryptor->decrypt($blob, $secret, $context);

        $this->assertSame($plaintext, $decrypted);
    }

    #[DataProvider('dataProviderConfigs')]
    public function testEncryptionIsRandomized(
        int $kdfSaltSize,
        int $dataKeySize,
        int $dataNonceSize,
        int $dataOverheadSize,
        int $kwKeySize,
        int $kwNonceSize,
        int $kwOverheadSize,
    ): void {
        [$kdf, $cipher, $kwCipher] = $this->createMocks(
            $kdfSaltSize,
            $dataKeySize,
            $dataNonceSize,
            $dataOverheadSize,
            $kwKeySize,
            $kwNonceSize,
            $kwOverheadSize,
        );

        $kdf->method('derive')->willReturn('kek');
        $cipher->method('encrypt')->willReturn('encrypted_data' . str_repeat("\x30", $dataOverheadSize));
        $kwCipher->method('encrypt')->willReturnCallback(static fn($dek, $key, $nonce) => $dek . str_repeat("\x10", $kwOverheadSize));

        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher, kwCipher: $kwCipher);

        $res1 = $cryptor->encrypt('data', 'secret');
        $res2 = $cryptor->encrypt('data', 'secret');

        $offset = 0;

        // 1. KDF salt (if $kdfSaltSize > 0)
        if ($kdfSaltSize > 0) {
            $salt1 = StringHelper::byteSubstring($res1, $offset, $kdfSaltSize);
            $salt2 = StringHelper::byteSubstring($res2, $offset, $kdfSaltSize);
            $this->assertNotSame($salt1, $salt2, 'KDF salt must be different for each encryption');
        }
        $offset += $kdfSaltSize;

        // 2. DEK nonce ($kwNonceSize > 0)
        if ($kwNonceSize > 0) {
            $dekNonce1 = StringHelper::byteSubstring($res1, $offset, $kwNonceSize);
            $dekNonce2 = StringHelper::byteSubstring($res2, $offset, $kwNonceSize);
            $this->assertNotSame($dekNonce1, $dekNonce2, 'DEK nonce must be different for each encryption');
        }
        $offset += $kwNonceSize;

        // 3. DEK (must be > 0)
        $dek1 = StringHelper::byteSubstring($res1, $offset, $dataKeySize);
        $dek2 = StringHelper::byteSubstring($res2, $offset, $dataKeySize);
        $this->assertNotSame($dek1, $dek2, 'DEK must be different for each encryption');
        $offset += $dataKeySize + $kwOverheadSize;

        // 4. Data nonce (if $dataNonceSize > 0)
        if ($dataNonceSize > 0) {
            $dataNonce1 = StringHelper::byteSubstring($res1, $offset, $dataNonceSize);
            $dataNonce2 = StringHelper::byteSubstring($res2, $offset, $dataNonceSize);
            $this->assertNotSame($dataNonce1, $dataNonce2, 'Data nonce must be different for each encryption');
        }
    }

    public function testDecryptThrowsWhenDataTooShort(): void
    {
        [$kdf, $cipher, $kwCipher] = $this->createMocks(...[
            'kdfSaltSize' => 16,
            'dataKeySize' => 32,
            'dataNonceSize' => 12,
            'dataOverheadSize' => 16,
            'kwKeySize' => 32,
            'kwNonceSize' => 12,
            'kwOverheadSize' => 16,
        ]);

        $cipher->method('encrypt')->willReturn('encrypted_data');

        $this->expectException(EncryptionException::class);

        $cryptor = new EnvelopeCryptor(kdf: $kdf, cipher: $cipher, kwCipher: $kwCipher);
        $cryptor->decrypt('short', 'secret');
    }

    private function createMocks(
        int $kdfSaltSize,
        int $dataKeySize,
        int $dataNonceSize,
        int $dataOverheadSize,
        int $kwKeySize,
        int $kwNonceSize,
        int $kwOverheadSize,
    ): array {
        $kdf = $this->createMock(KdfInterface::class);
        $kdf->method('getSaltSize')->willReturn($kdfSaltSize);

        $cipher = $this->createMock(CipherInterface::class);
        $cipher->method('getKeySize')->willReturn($dataKeySize);
        $cipher->method('getNonceSize')->willReturn($dataNonceSize);
        $cipher->method('getOverheadSize')->willReturn($dataOverheadSize);

        $kwCipher = $this->createMock(CipherInterface::class);
        $kwCipher->method('getKeySize')->willReturn($kwKeySize);
        $kwCipher->method('getNonceSize')->willReturn($kwNonceSize);
        $kwCipher->method('getOverheadSize')->willReturn($kwOverheadSize);

        return [$kdf, $cipher, $kwCipher];
    }

    /**
     * [kdfSaltSize, kwKeySize, kwNonceSize, kwOverheadSize, dataKeySize, dataNonceSize, dataOverheadSize]
     */
    public static function dataProviderConfigs(): iterable
    {
        yield [
            'kdfSaltSize' => 16,
            'dataKeySize' => 32,
            'dataNonceSize' => 12,
            'dataOverheadSize' => 16,
            'kwKeySize' => 32,
            'kwNonceSize' => 12,
            'kwOverheadSize' => 16,
        ];
        // kdf without salt
        yield [
            'kdfSaltSize' => 0,
            'dataKeySize' => 32,
            'dataNonceSize' => 12,
            'dataOverheadSize' => 16,
            'kwKeySize' => 32,
            'kwNonceSize' => 12,
            'kwOverheadSize' => 16,
        ];
        // kdf without salt, kw ciper without nonce
        yield [
            'kdfSaltSize' => 0,
            'dataKeySize' => 32,
            'dataNonceSize' => 12,
            'dataOverheadSize' => 16,
            'kwKeySize' => 32,
            'kwNonceSize' => 0,
            'kwOverheadSize' => 16,
        ];
        // kdf without salt, data ciper without nonce
        yield [
            'kdfSaltSize' => 0,
            'dataKeySize' => 32,
            'dataNonceSize' => 0,
            'dataOverheadSize' => 16,
            'kwKeySize' => 32,
            'kwNonceSize' => 12,
            'kwOverheadSize' => 16,
        ];
        // kdf without salt, kw/data ciper without nonce
        yield [
            'kdfSaltSize' => 0,
            'dataKeySize' => 32,
            'dataNonceSize' => 0,
            'dataOverheadSize' => 16,
            'kwKeySize' => 32,
            'kwNonceSize' => 0,
            'kwOverheadSize' => 16,
        ];
        // kw/data ciper without nonce
        yield [
            'kdfSaltSize' => 16,
            'dataKeySize' => 32,
            'dataNonceSize' => 0,
            'dataOverheadSize' => 16,
            'kwKeySize' => 32,
            'kwNonceSize' => 0,
            'kwOverheadSize' => 16,
        ];
    }
}
