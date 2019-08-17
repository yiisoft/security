<?php

namespace Yiisoft\Security\Tests;

require_once __DIR__ . '/MockHelper.php';

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\DataIsTamperedException;
use Yiisoft\Security\Mac;
use Yiisoft\Security\MockHelper;

class MacTest extends TestCase
{
    protected function tearDown()
    {
        MockHelper::resetMocks();
    }

    public function testOriginalMessageIsExtracted(): void
    {
        $mac = new Mac();
        $data = 'known data';
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

        $this->expectException(DataIsTamperedException::class);
        $mac->getMessage($signedData, $key);
    }

    public function testSignException()
    {
        $this->expectException(\RuntimeException::class);

        MockHelper::$mock_hash_hmac = false;
        $mac = new Mac();
        $mac->sign('test', 'test');
    }

    public function testGetMessageException()
    {
        $this->expectException(\RuntimeException::class);

        $mac = new Mac('crc32');
        $mac->getMessage('test', 'test');
    }
}
