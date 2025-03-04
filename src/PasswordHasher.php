<?php

declare(strict_types=1);

namespace Yiisoft\Security;

use InvalidArgumentException;
use SensitiveParameter;

use function password_hash;
use function password_needs_rehash;
use function password_verify;

use const PASSWORD_BCRYPT;
use const PASSWORD_DEFAULT;

/**
 * PasswordHasher allows generating password hash and verifying passwords against a hash.
 */
final class PasswordHasher
{
    private array $parameters;

    private const SAFE_PARAMETERS = [
        PASSWORD_BCRYPT => [
            'cost' => 13,
        ],
    ];

    /**
     * @param string|null $algorithm Algorithm to use. If not specified, PHP chooses safest algorithm available in the
     * current version of PHP.
     * @param array|null $parameters Algorithm parameters. If not specified, safe defaults are used.
     *
     * @see https://www.php.net/manual/en/function.password-hash.php
     */
    public function __construct(
        private readonly string|null $algorithm = PASSWORD_DEFAULT,
        array|null $parameters = null,
    ) {
        if ($parameters === null) {
            $this->parameters = self::SAFE_PARAMETERS[$this->algorithm] ?? [];
        } else {
            $this->parameters = $parameters;
        }
    }

    /**
     * Generates a secure hash from a password and a random salt.
     *
     * The generated hash can be stored in database.
     * Later when a password needs to be validated, the hash can be fetched and passed
     * to {@see validate()}. For example,
     *
     * ```php
     * // generates the hash (usually done during user registration or when the password is changed)
     * $hash = (new PasswordHasher())->hash($password);
     * // ...save $hash in database...
     *
     * // during login, validate if the password entered is correct using $hash fetched from database
     * if ((new PasswordHasher())->validate($password, $hash)) {
     *     // password is good
     * } else {
     *     // password is bad
     * }
     * ```
     *
     * @param string $password The password to be hashed.
     *
     * @return string The password hash string. The output length might increase
     * in future versions of PHP (https://php.net/manual/en/function.password-hash.php)
     *
     * @see validate()
     * @psalm-suppress InvalidNullableReturnType
     * @psalm-suppress NullableReturnStatement
     */
    public function hash(
        #[SensitiveParameter]
        string $password
    ): string {
        return password_hash($password, $this->algorithm, $this->parameters);
    }

    /**
     * Verifies a password against a hash.
     *
     * @param string $password The password to verify.
     * @param string $hash The hash to verify the password against.
     *
     * @throws InvalidArgumentException on bad password/hash parameters or if crypt() with Blowfish hash is not
     * available.
     *
     * @return bool whether the password is correct.
     *
     * @see hash()
     */
    public function validate(
        #[SensitiveParameter]
        string $password,
        #[SensitiveParameter]
        string $hash
    ): bool {
        if ($password === '') {
            throw new InvalidArgumentException('Password must be a string and cannot be empty.');
        }

        return password_verify($password, $hash);
    }

    /**
     * Verifies if a hash needs rehash.
     *
     * @param string $hash The hash to verify.
     *
     * @return bool Whether rehash is needed.
     *
     * @see password_needs_rehash()
     */
    public function needsRehash(
        #[SensitiveParameter]
        string $hash
    ): bool {
        return password_needs_rehash($hash, $this->algorithm, $this->parameters);
    }
}
