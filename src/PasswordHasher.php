<?php
namespace Yiisoft\Security;

/**
 * PasswordHasher allows generating password hash and verifying passwords against a hash.
 */
class PasswordHasher
{
    /**
     * @var int Default cost used for password hashing.
     * Allowed value is between 4 and 31.
     * @see hash()
     */
    private $cost;

    /**
     * @param int $cost
     * @see https://www.php.net/manual/en/function.password-hash.php on how to choose cost
     */
    public function __construct(int $cost = 13)
    {
        $this->cost = $cost;
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
     * $hash = Yii::getApp()->getSecurity()->hash($password);
     * // ...save $hash in database...
     *
     * // during login, validate if the password entered is correct using $hash fetched from database
     * if (Yii::getApp()->getSecurity()->validate($password, $hash)) {
     *     // password is good
     * } else {
     *     // password is bad
     * }
     * ```
     *
     * @param string $password The password to be hashed.
     * @param int $cost Cost parameter used by the Blowfish hash algorithm.
     * The higher the value of cost,
     * the longer it takes to generate the hash and to verify a password against it. Higher cost
     * therefore slows down a brute-force attack. For best protection against brute-force attacks,
     * set it to the highest value that is tolerable on production servers. The time taken to
     * compute the hash doubles for every increment by one of $cost.
     * @return string The password hash string. The output length might increase
     * in future versions of PHP (http://php.net/manual/en/function.password-hash.php)
     * @throws \Exception on bad password parameter or cost parameter.
     * @see validate()
     */
    public function hash(string $password, int $cost = null): string
    {
        if ($cost === null) {
            $cost = $this->cost;
        }

        return password_hash($password, PASSWORD_DEFAULT, ['cost' => $cost]);
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
