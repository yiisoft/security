<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use RuntimeException;
use SensitiveParameter;
use function
    mb_strlen,
    mb_substr;

/**
 * VersionedCryptor provides a wrapper for multiple cryptors, identifying them by a version prefix.
 * 
 * This allows for seamless migration between different encryption algorithms or configurations.
 * Each encrypted message is prefixed with a version identifier of a fixed size.
 */
final class VersionedCryptor implements CryptorInterface
{
    /**
     * @var array<string, CryptorInterface> Storage for registered cryptors indexed by their version identifier.
     */
    private readonly array $cryptors;

    /**
     * @param array<string, CryptorInterface> $cryptors List of cryptors where the key is the version string and the value is a CryptorInterface instance.
     * @param string $currentVersion The version identifier to be used for new encryptions.
     * @param int $versionSize The fixed byte length of the version prefix.
     * 
     * @throws RuntimeException If the current version is missing or identifiers have invalid length.
     */
    public function __construct(
        array $cryptors,
        private readonly string $currentVersion,
        private readonly int $versionSize,
    ) {
        if ($versionSize < 1) {
            throw new RuntimeException('Version size must be greather than 0.');
        }

        $this->cryptors = $this->validateAndNormalize($cryptors);

        if (!isset($this->cryptors[$this->currentVersion])) {
            throw new RuntimeException("Current version '{$this->currentVersion}' is not registered.");
        }
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        $payload = $this->cryptors[$this->currentVersion]->encrypt($data, $secret, $context);

        return $this->currentVersion . $payload;
    }

    /**
     * {@inheritdoc}
     * 
     * @throws RuntimeException If the version prefix is not recognized or data is malformed.
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        if (mb_strlen($data, '8bit') < $this->versionSize) {
            throw new RuntimeException('Encrypted data is too short to contain a version identifier.');
        }
        
        $version = mb_substr($data, 0, $this->versionSize, '8bit');
        $cryptor = $this->cryptors[$version]
                ?? throw new RuntimeException('version not found');

        $payload = mb_substr($data, $this->versionSize, null, '8bit');

        return $cryptor->decrypt($payload, $secret, $context);
    }

    /**
     * Validates input array and ensures all version identifiers match the required size.
     * 
     * @param array $cryptors Map of version => cryptor instances.
     * @return array<string, CryptorInterface> Normalized array.
     * @throws RuntimeException If validation fails.
     */
    private function validateAndNormalize(array $cryptors): array
    {
        $normalized = [];
        foreach ($cryptors as $version => $cryptor) {
            $version = (string) $version;

            if (!$cryptor instanceof CryptorInterface) {
                throw new RuntimeException('All cryptors must implement CryptorInterface.');
            }

            if (mb_strlen($version, '8bit') !== $this->versionSize) {
                throw new RuntimeException("Version identifier '$version' must be exactly {$this->versionSize} bytes.");
            }

            $normalized[$version] = $cryptor;
        }

        return $normalized;
    }
}
