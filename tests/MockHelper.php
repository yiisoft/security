<?php

declare(strict_types=1);

namespace Yiisoft\Security;

function openssl_encrypt($data, $method, $key, $options = 0, $iv = '')
{
    return MockHelper::$mock_openssl_encrypt ?? \openssl_encrypt($data, $method, $key, $options, $iv);
}

function openssl_decrypt($data, $method, $password, $options = 1, $iv = '')
{
    return MockHelper::$mock_openssl_decrypt ?? \openssl_decrypt($data, $method, $password, $options, $iv);
}

class MockHelper
{
    /**
     * @var false|string|null value to be returned by mocked openssl_encrypt() function.
     * null means normal openssl_encrypt() behavior.
     */
    public static $mock_openssl_encrypt;
    /**
     * @var false|string|null value to be returned by mocked openssl_decrypt() function.
     * null means normal openssl_decrypt() behavior.
     */
    public static $mock_openssl_decrypt;

    public static function resetMocks(): void
    {
        static::$mock_openssl_encrypt = null;
        static::$mock_openssl_decrypt = null;
    }
}
