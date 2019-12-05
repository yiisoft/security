<?php

namespace Yiisoft\Security\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Security\PasswordHasher;

class PasswordHasherTest extends TestCase
{
    public function testPasswordHashWithDefaults(): void
    {
        $password = new PasswordHasher();

        $secret = 'secret';
        $hash = $password->hash($secret);

        $this->assertTrue($password->validate($secret, $hash));
        $this->assertFalse($password->validate('test', $hash));
    }

    public function testPasswordHash(): void
    {
        $password = new PasswordHasher(
            PASSWORD_BCRYPT, [
            // minimum blowfish's value is enough for tests
            'cost' => 4,
        ]
        );

        $secret = 'secret';
        $hash = $password->hash($secret);
        $this->assertTrue($password->validate($secret, $hash));
        $this->assertFalse($password->validate('test', $hash));
    }

    public function testValidateEmptyPasswordException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $password = new PasswordHasher();
        $password->validate('', 'test');
    }

    /**
     * In PHP 7.4 password hashing algorithm identifiers are now nullable strings rather than integers.
     */
    public function testAlgorithmString(): void
    {
        $password = new PasswordHasher('test');
        $this->assertTrue(true);
    }
}
