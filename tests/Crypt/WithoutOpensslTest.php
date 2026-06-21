<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypt;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yiisoft\Security\Crypt;

use function extension_loaded;

final class WithoutOpensslTest extends TestCase
{
    public function testOpensslNotLoadedException(): void
    {
        if (extension_loaded('openssl')) {
            $this->markTestSkipped('openssl extension is loaded');
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Encryption requires the OpenSSL PHP extension.');
        new Crypt();
    }
}
