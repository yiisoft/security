<?php
namespace Yiisoft\Security;

use Yiisoft\Strings\StringHelper;

final class Crypt
{
    /**
     * @var string The cipher to use for encryption and decryption.
     */
    private $cipher;

    /**
     * @var array[] Look-up table of block sizes and key sizes for each supported OpenSSL cipher.
     *
     * In each element, the key is one of the ciphers supported by OpenSSL {@see openssl_get_cipher_methods()}.
     * The value is an array of two integers, the first is the cipher's block size in bytes and the second is
     * the key size in bytes.
     *
     * > Note: Yii's encryption protocol uses the same size for cipher key, HMAC signature key and key
     * derivation salt.
     */
    private const ALLOWED_CIPHERS = [
        'AES-128-CBC' => [16, 16],
        'AES-192-CBC' => [16, 24],
        'AES-256-CBC' => [16, 32],
    ];

    /**
     * @var string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512.
     * @see http://php.net/manual/en/function.hash-algos.php
     */
    private $kdfAlgorithm = 'sha256';

    /**
     * @var string HKDF info value for derivation of message authentication key.
     */
    private $authKeyInfo = 'AuthorizationKey';
    /**
     * @var int derivation iterations count.
     * Set as high as possible to hinder dictionary password attacks.
     */
    private $derivationIterations = 100000;

    public function __construct(string $cipher = 'AES-128-CBC')
    {
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException('Encryption requires the OpenSSL PHP extension');
        }
        if (!isset(self::ALLOWED_CIPHERS[$cipher][0], self::ALLOWED_CIPHERS[$cipher][1])) {
            throw new \RuntimeException($cipher . ' is not an allowed cipher');
        }

        $this->cipher = $cipher;
    }

    public function withKdfAlgorithm(string $algorithm): self
    {
        $new = clone $this;
        $new->kdfAlgorithm = $algorithm;
        return $new;
    }

    public function withAuthKeyInfo(string $info): self
    {
        $new = clone $this;
        $new->authKeyInfo = $info;
        return $new;
    }

    public function withDerivationInterations(int $interations): self
    {
        $new = clone $this;
        $new->derivationIterations = $interations;
        return $new;
    }

    /**
     * Encrypts data using a password.
     * Derives keys for encryption and authentication from the password using PBKDF2 and a random salt,
     * which is deliberately slow to protect against dictionary attacks. Use {@see encryptByKey()} to
     * encrypt fast using a cryptographic key rather than a password. Key derivation time is
     * determined by {@see $derivationIterations}}, which should be set as high as possible.
     * The encrypted data includes a keyed message authentication code (MAC) so there is no need
     * to hash input or output data.
     * > Note: Avoid encrypting with passwords wherever possible. Nothing can protect against
     * poor-quality or compromised passwords.
     * @param string $data the data to encrypt
     * @param string $password the password to use for encryption
     * @return string the encrypted data
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL error
     * @see decryptByPassword()
     * @see encryptByKey()
     */
    public function encryptByPassword(string $data, string $password): string
    {
        return $this->encrypt($data, true, $password, '');
    }

    /**
     * Encrypts data using a cryptographic key.
     * Derives keys for encryption and authentication from the input key using HKDF and a random salt,
     * which is very fast relative to {@see encryptByPassword()}. The input key must be properly
     * random — use {@see random_bytes()} to generate keys.
     * The encrypted data includes a keyed message authentication code (MAC) so there is no need
     * to hash input or output data.
     * @param string $data the data to encrypt
     * @param string $inputKey the input to use for encryption and authentication
     * @param string $info context/application specific information, e.g. a user ID
     * See [RFC 5869 Section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2) for more details.
     * @return string the encrypted data
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL error
     * @see decryptByKey()
     * @see encryptByPassword()
     */
    public function encryptByKey(string $data, string $inputKey, string $info = ''): string
    {
        return $this->encrypt($data, false, $inputKey, $info);
    }

    /**
     * Verifies and decrypts data encrypted with {@see encryptByPassword()}.
     * @param string $data the encrypted data to decrypt
     * @param string $password the password to use for decryption
     * @return string the decrypted data
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL errors
     * @throws AuthenticationFailure on authentication failure
     * @see encryptByPassword()
     */
    public function decryptByPassword(string $data, string $password): string
    {
        return $this->decrypt($data, true, $password, '');
    }

    /**
     * Verifies and decrypts data encrypted with {@see encryptByKey()}.
     * @param string $data the encrypted data to decrypt
     * @param string $inputKey the input to use for encryption and authentication
     * @param string $info context/application specific information, e.g. a user ID
     * See [RFC 5869 Section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2) for more details.
     * @return string the decrypted data
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL errors
     * @throws AuthenticationFailure on authentication failure
     * @see encryptByKey()
     */
    public function decryptByKey($data, $inputKey, $info = ''): string
    {
        return $this->decrypt($data, false, $inputKey, $info);
    }

    /**
     * Encrypts data.
     *
     * @param string $data data to be encrypted
     * @param bool $passwordBased set true to use password-based key derivation
     * @param string $secret the encryption password or key
     * @param string $info context/application specific information, e.g. a user ID
     * See [RFC 5869 Section 3.2](https://tools.ietf.org/html/rfc5869#section-3.2) for more details.
     *
     * @return string the encrypted data
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL error
     * @see decrypt()
     */
    private function encrypt(string $data, bool $passwordBased, string $secret, string $info = ''): string
    {
        [$blockSize, $keySize] = self::ALLOWED_CIPHERS[$this->cipher];

        $keySalt = random_bytes($keySize);
        if ($passwordBased) {
            $key = hash_pbkdf2($this->kdfAlgorithm, $secret, $keySalt, $this->derivationIterations, $keySize, true);
        } else {
            $key = hash_hkdf($this->kdfAlgorithm, $secret, $keySize, $info, $keySalt);
        }

        $iv = random_bytes($blockSize);

        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new \RuntimeException('OpenSSL failure on encryption: ' . openssl_error_string());
        }

        $authKey = hash_hkdf($this->kdfAlgorithm, $key, $keySize, $this->authKeyInfo);
        $signed = (new Mac())->sign($iv . $encrypted, $authKey);

        /*
         * Output: [keySalt][MAC][IV][ciphertext]
         * - keySalt is KEY_SIZE bytes long
         * - MAC: message authentication code, length same as the output of MAC_HASH
         * - IV: initialization vector, length $blockSize
         */
        return $keySalt . $signed;
    }

    /**
     * Decrypts data.
     *
     * @param string $data encrypted data to be decrypted.
     * @param bool $passwordBased set true to use password-based key derivation
     * @param string $secret the decryption password or key
     * @param string $info context/application specific information, @see encrypt()
     *
     * @return string the decrypted data
     * @throws \RuntimeException on OpenSSL not loaded
     * @throws \Exception on OpenSSL errors
     * @throws AuthenticationFailure on authentication failure
     * @see encrypt()
     */
    private function decrypt(string $data, bool $passwordBased, string $secret, string $info): string
    {
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException('Encryption requires the OpenSSL PHP extension');
        }
        if (!isset(self::ALLOWED_CIPHERS[$this->cipher][0], self::ALLOWED_CIPHERS[$this->cipher][1])) {
            throw new \RuntimeException($this->cipher . ' is not an allowed cipher');
        }

        [$blockSize, $keySize] = self::ALLOWED_CIPHERS[$this->cipher];

        $keySalt = StringHelper::byteSubstr($data, 0, $keySize);
        if ($passwordBased) {
            $key = hash_pbkdf2($this->kdfAlgorithm, $secret, $keySalt, $this->derivationIterations, $keySize, true);
        } else {
            $key = hash_hkdf($this->kdfAlgorithm, $secret, $keySize, $info, $keySalt);
        }

        $authKey = hash_hkdf($this->kdfAlgorithm, $key, $keySize, $this->authKeyInfo);

        try {
            $data = (new Mac())->getMessage(StringHelper::byteSubstr($data, $keySize), $authKey);
        } catch (DataIsTampered $e) {
            throw new AuthenticationFailure('Failed to decrypt data');
        }

        $iv = StringHelper::byteSubstr($data, 0, $blockSize);
        $encrypted = StringHelper::byteSubstr($data, $blockSize);

        $decrypted = openssl_decrypt($encrypted, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new \RuntimeException('OpenSSL failure on decryption: ' . openssl_error_string());
        }

        return $decrypted;
    }
}
