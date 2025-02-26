<?php

declare(strict_types=1);

namespace Yiisoft\Security;

use SensitiveParameter;
use Yiisoft\Strings\StringHelper;

/**
 * Provides ability to sign a message with a MAC (message authentication). Signed message contains both original
 * message and a MAC hash. When obtaining original message from signed message using a key an exception is thrown
 * if message was altered.
 */
final class Mac
{
    /**
     * @param string $algorithm Hash algorithm for message authentication. Recommend sha256, sha384 or sha512.
     *
     * @see https://php.net/manual/en/function.hash-algos.php
     */
    public function __construct(
        private readonly string $algorithm = 'sha256'
    ) {
    }

    /**
     * Prefixes data with a keyed sign value so that it can later be detected if it is tampered.
     *
     * There is no need to sign inputs or outputs of {@see Crypt::encryptByKey()} or {@see Crypt::encryptByPassword()}
     * as those methods perform the task.
     *
     * @param string $data The data to be protected.
     * @param string $key The secret key to be used for generating sign. Should be a secure
     * cryptographic key.
     * @param bool $rawHash Whether the generated sign value is in raw binary format. If false, lowercase
     * hex digits will be generated.
     *
     * @throws \RuntimeException When HMAC generation fails.
     *
     * @return string The data prefixed with the keyed sign.
     *
     * @see validate()
     * @see generateBytes()
     * @see hkdf()
     * @see pbkdf2()
     */
    public function sign(
        string $data,
        #[SensitiveParameter]
        string $key,
        bool $rawHash = false
    ): string {
        $hash = hash_hmac($this->algorithm, $data, $key, $rawHash);
        if (!$hash) {
            throw new \RuntimeException("Failed to generate HMAC with hash algorithm: {$this->algorithm}.");
        }

        return $hash . $data;
    }

    /**
     * Get original message from signed message.
     *
     * @param string $data The data to be validated. The data must be previously
     * generated by {@see sign()}.
     * @param string $key The secret key that was previously used to generate the sign for the data in {@see sign()}.
     * function to see the supported hashing algorithms on your system. This must be the same
     * as the value passed to {@see sign()} when generating the hash signature for the data.
     * @param bool $rawHash This should take the same value as when you generate the data using {@see sign()}.
     * It indicates whether the sign value in the data is in binary format. If false, it means the hash value consists
     * of lowercase hex digits only.
     *
     * @throws \RuntimeException When HMAC generation fails.
     * @throws DataIsTamperedException If the given data is tampered.
     *
     * @return string The real data with the signature stripped off.
     *
     * @see hash()
     */
    public function getMessage(
        string $data,
        #[SensitiveParameter]
        string $key,
        bool $rawHash = false
    ): string {
        $test = hash_hmac($this->algorithm, '', '', $rawHash);
        if (!$test) {
            throw new \RuntimeException("Failed to generate HMAC with hash algorithm: {$this->algorithm}.");
        }
        $hashLength = StringHelper::byteLength($test);
        if (StringHelper::byteLength($data) >= $hashLength) {
            $hash = StringHelper::byteSubstring($data, 0, $hashLength);
            $pureData = StringHelper::byteSubstring($data, $hashLength, null);

            $calculatedHash = hash_hmac($this->algorithm, $pureData, $key, $rawHash);

            if (hash_equals($hash, $calculatedHash)) {
                return $pureData;
            }
        }

        throw new DataIsTamperedException();
    }
}
