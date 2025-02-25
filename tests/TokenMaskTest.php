<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Yiisoft\Security\TokenMask;

final class TokenMaskTest extends TestCase
{
    #[DataProvider('maskProvider')]
    public function testMaskingAndUnmasking($unmaskedToken): void
    {
        $maskedToken = TokenMask::apply($unmaskedToken);

        $this->assertGreaterThan(mb_strlen($unmaskedToken, '8bit') * 2, mb_strlen($maskedToken, '8bit'));
        $this->assertEquals($unmaskedToken, TokenMask::remove($maskedToken));
    }

    public function testUnMaskingInvalidStrings(): void
    {
        $this->assertEquals('', TokenMask::remove(''));
        $this->assertEquals('', TokenMask::remove('1'));
    }

    public function testMaskingInvalidStrings(): void
    {
        $this->expectException(\Error::class);
        TokenMask::apply('');
    }

    public static function maskProvider(): array
    {
        return [
            ['1'],
            ['SimpleToken'],
            ['Token with special characters: %d1    5"'],
            ['Token with UTF8 character: †'],
        ];
    }

    public function testUnmaskTokenWithOddLength(): void
    {
        $this->assertEquals('', TokenMask::remove('YWJj'));
    }
}
