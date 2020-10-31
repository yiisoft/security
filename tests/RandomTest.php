<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\Random;

final class RandomTest extends TestCase
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
        $this->assertMatchesRegularExpression('/[A-Za-z0-9_-]+/', $key);
    }

    public function testInvalidLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Random::string(0);
    }
}
