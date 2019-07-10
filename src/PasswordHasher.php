<?php
namespace Yiisoft\Security;

/**
 * PasswordHasher allows generating password hash and verifying passwords against a hash.
 */
class PasswordHasher
{
    private $algorithm;
    private $parameters;

    private const SAFE_PARAMETERS = [
        PASSWORD_BCRYPT => [
            'cost' => 13,
        ],
        PASSWORD_ARGON2I => null,
        PASSWORD_ARGON2ID => null,
    ];

    /**
     * @see https://www.php.net/manual/en/function.password-hash.php
     */
    public function __construct(int $algorithm = PASSWORD_DEFAULT, array $parameters = null)
    {
        $this->algorithm = $algorithm;

        if ($parameters === null) {
            $parameters = self::SAFE_PARAMETERS[$algorithm];
        }
        $this->parameters = $parameters;
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
     * @return string The password hash string. The output length might increase
     * in future versions of PHP (http://php.net/manual/en/function.password-hash.php)
     * @see validate()
     */
    public function hash(string $password): string
    {
        return password_hash($password, $this->algorithm, $this->parameters);
    }

    /**
     * Verifies a password against a hash.
     * @param string $password The password to verify.
     * @param string $hash The hash to verify the password against.
     * @return bool whether the password is correct.
     * @throws \InvalidArgumentException on bad password/hash parameters or if crypt() with Blowfish hash is not
     * available.
     * @see hash()
     */
    public function validate(string $password, string $hash): bool
    {
        if ($password === '') {
            throw new \InvalidArgumentException('Password must be a string and cannot be empty.');
        }

        return password_verify($password, $hash);
    }
}
