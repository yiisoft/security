<?php

declare(strict_types=1);

namespace Yiisoft\Security;

/**
 * Mock for the hash_hmac() function
 *
 * @param $algo
 * @param $data
 * @param $key
 * @param bool $raw_output
 *
 * @return string
 */
function hash_hmac($algo, $data, $key, $raw_output = false)
{
    return MockHelper::$mock_hash_hmac ?? \hash_hmac($algo, $data, $key, $raw_output);
}

function extension_loaded($name)
{
    return MockHelper::$mock_extension_loaded ?? \extension_loaded($name);
}

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
     * @var bool|string|null value to be returned by mocked hash_hmac() function.
     * null means normal hash_hmac() behavior.
     */
    public static $mock_hash_hmac;
    /**
     * @var bool|null value to be returned by mocked extension_loaded() function.
     * null means normal extension_loaded() behavior.
     */
    public static ?bool $mock_extension_loaded = null;
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
        static::$mock_hash_hmac = null;
        static::$mock_extension_loaded = null;
        static::$mock_openssl_encrypt = null;
        static::$mock_openssl_decrypt = null;
    }
}
