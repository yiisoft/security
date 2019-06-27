<?php
namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\PasswordHasher;

class PasswordTest extends TestCase
{
    public function testPasswordHash(): void
    {
        // minimum blowfish's value is enough for tests
        $password = new PasswordHasher(4);

        $secret = 'secret';
        $hash = $password->hash($secret);
        $this->assertTrue($password->validate($secret, $hash));
        $this->assertFalse($password->validate('test', $hash));
    }
}
