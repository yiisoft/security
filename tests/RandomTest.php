<?php

namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\Random;

class RandomTest extends TestCase
{
    public function testRandomStringRespectsLength(): void
    {
        $length = 21;
        $key = Random::string($length);
        $this->assertEquals($length, strlen($key));
    }

    public function testRandomStringValidSymbols(): void
    {
        $key = Random::string(100);
        $this->assertRegExp('/[A-Za-z0-9_-]+/', $key);
    }

    public function testInvalidLength()
    {
        $this->expectException(\InvalidArgumentException::class);
        $key = Random::string(0);
    }
}
