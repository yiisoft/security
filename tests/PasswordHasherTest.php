<?php
namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\PasswordHasher;

class PasswordHasherTest extends TestCase
{
    public function testPasswordHash(): void
    {
        $password = new PasswordHasher(PASSWORD_BCRYPT, [
            // minimum blowfish's value is enough for tests
            'cost' => 4,
        ]);

        $secret = 'secret';
        $hash = $password->hash($secret);
        $this->assertTrue($password->validate($secret, $hash));
        $this->assertFalse($password->validate('test', $hash));
    }
}
