<?php declare(strict_types=1);

namespace Yiisoft\Security;

use Yiisoft\Strings\StringHelper;

/**
 * Random allows generating random values.
 *
 * Currently it has a single method "string".
 * The following extras are available via PHP directly:
 *
 * - `random_bytes()` for bytes. Note that output may not be ASCII.
 * - `random_int()` for integers.
 */
final class Random
{
    /**
     * Generates a random string of specified length.
     * The string generated matches [A-Za-z0-9_-]+ and is transparent to URL-encoding.
     *
     * @param int $length the length of the key in characters
     * @return string the generated random key
     * @throws \Exception on failure.
     */
    public static function string(int $length = 32): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('First parameter ($length) must be greater than 0');
        }

        $bytes = random_bytes($length);
        return substr(StringHelper::base64UrlEncode($bytes), 0, $length);
    }
}
