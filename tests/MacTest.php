<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\DataIsTamperedException;
use Yiisoft\Security\Mac;
use RuntimeException;

use function strlen;

final class MacTest extends TestCase
{
    public function testSignMessage(): void
    {
        $mac = new Mac();
        $data = 'known data';
        $key = 'secret';

        $signedData = $mac->sign($data, $key);

        $this->assertNotSame($data, $signedData);
        $this->assertStringContainsString($data, $signedData);
    }

    public function testOriginalMessageIsExtracted(): void
    {
        $mac = new Mac();
        $data = 'known data';
        $key = 'secret';

        $signedData = $mac->sign($data, $key);

        $this->assertSame($data, $mac->getMessage($signedData, $key));
    }

    public function testExtractEmptyMessage(): void
    {
        $mac = new Mac();
        $data = '';
        $key = 'secret';

        $signedData = $mac->sign($data, $key);

        $this->assertNotSame($data, $signedData);
        $this->assertSame($data, $mac->getMessage($signedData, $key));
    }

    public function testDataTamperingIsDetected(): void
    {
        $mac = new Mac();
        $data = 'known data';
        $key = 'secret';

        $signedData = $mac->sign($data, $key);
        $signedData[strlen($signedData) - 1] = 'A';

        $this->expectExceptionMessage('Data does not match signature.');
        $this->expectException(DataIsTamperedException::class);
        $mac->getMessage($signedData, $key);
    }

    public function testSignException(): void
    {
        $mac = new Mac('xxx');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Failed to generate HMAC with hash algorithm: xxx.');
        $mac->sign('test', 'test');
    }

    public function testGetMessageException(): void
    {
        $mac = new Mac('xxx');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Failed to generate HMAC with hash algorithm: xxx.');
        $mac->getMessage(
            data: 'test',
            key: 'test',
        );
    }

    public function testGetFromDamagedMessageException(): void
    {
        $mac = new Mac();
        $data = 'known data';
        $key = 'secret';
        $signedData = $mac->sign($data, $key);
        $damagedData = substr($signedData, 0, -1);

        $this->expectException(RuntimeException::class);

        $mac = new Mac();
        $mac->getMessage($damagedData, $key);
    }

    public function testGetFromTooShortMessageException(): void
    {
        $mac = new Mac();
        $data = 'known data';
        $key = 'secret';
        $signedData = $mac->sign($data, $key);
        $damagedData = substr($signedData, 0, -strlen($data) - 1);

        $this->expectException(RuntimeException::class);

        $mac = new Mac();
        $mac->getMessage($damagedData, $key);
    }
}
