<?php
namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\DataIsTamperedException;
use Yiisoft\Security\Mac;

class MacTest extends TestCase
{
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
}
