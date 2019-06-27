<?php
namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\TokenMasker;

class TokenMaskerTest extends TestCase
{
    /**
     * @dataProvider maskProvider
     * @param mixed $unmaskedToken
     * @throws \Exception
     */
    public function testMaskingAndUnmasking($unmaskedToken): void
    {
        $maskedToken = TokenMasker::mask($unmaskedToken);

        $this->assertGreaterThan(mb_strlen($unmaskedToken, '8bit') * 2, mb_strlen($maskedToken, '8bit'));
        $this->assertEquals($unmaskedToken, TokenMasker::unmask($maskedToken));
    }

    public function testUnMaskingInvalidStrings(): void
    {
        $this->assertEquals('', TokenMasker::unmask(''));
        $this->assertEquals('', TokenMasker::unmask('1'));
    }

    public function testMaskingInvalidStrings(): void
    {
        $this->expectException(\Error::class);
        TokenMasker::mask('');
    }

    public function maskProvider(): array
    {
        return [
            ['1'],
            ['SimpleToken'],
            ['Token with special characters: %d1    5"'],
            ['Token with UTF8 character: †'],
        ];
    }
}
