<?php

declare(strict_types=1);

namespace Yiisoft\Security;

use SensitiveParameter;
use Yiisoft\Strings\StringHelper;
use Exception;
use InvalidArgumentException;

use function is_int;

/**
 * TokenMask helps to mitigate BREACH attack by randomizing how token is outputted on each request.
 * A random mask is applied to the token making the string always unique.
 */
final class TokenMask
{
    /**
     * Masks a token to make it incompressible.
     * Applies a random mask to the token and prepends the mask used to the result making the string always unique.
     *
     * @param string $token An unmasked token.
     *
     * @throws Exception if unable to securely generate random bytes
     * @throws InvalidArgumentException if the token is empty.
     *
     * @return string A masked token.
     */
    public static function apply(
        #[SensitiveParameter]
        string $token,
    ): string {
        // The number of bytes in a mask is always equal to the number of bytes in a token.
        $maskLength = StringHelper::byteLength($token);
        if ($maskLength < 1) {
            throw new InvalidArgumentException('Token must not be empty.');
        }
        $mask = random_bytes($maskLength);
        return StringHelper::base64UrlEncode($mask . ($mask ^ $token));
    }

    /**
     * Unmasks a token previously masked by `mask`.
     *
     * @param string $maskedToken A masked token.
     *
     * @return string An unmasked token, or an empty string in case of token format is invalid.
     */
    public static function remove(
        #[SensitiveParameter]
        string $maskedToken,
    ): string {
        $decoded = StringHelper::base64UrlDecode($maskedToken);
        $length = StringHelper::byteLength($decoded) / 2;
        // Check if the masked token has an even length.
        if (!is_int($length)) {
            return '';
        }

        return StringHelper::byteSubstring($decoded, $length, $length) ^ StringHelper::byteSubstring($decoded, 0, $length);
    }
}
