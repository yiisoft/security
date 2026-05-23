<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use RuntimeException;
use SensitiveParameter;
use Yiisoft\Strings\StringHelper;

use function bin2hex;

/**
 * VersionedCryptor wraps multiple cryptors and adds a version prefix to the ciphertext.
 * This enables seamless migration between different encryption algorithms or key lengths.
 * Each encrypted message begins with a fixed‑length version identifier.
 */
final class VersionedCryptor implements CryptorInterface
{
    /**
     * @var array<string, CryptorInterface> Storage for registered cryptors indexed by their version identifier.
     */
    private readonly array $cryptors;

    /**
     * @param array<string, CryptorInterface> $cryptors List of cryptors indexed by version string.
     * @param string $currentVersion Version identifier used for new encryptions.
     * @param int $versionSize Fixed byte length of the version prefix (must be >=1).
     *
     * @throws RuntimeException If validation fails or current version is not registered.
     */
    public function __construct(
        array $cryptors,
        private readonly string $currentVersion,
        private readonly int $versionSize,
    ) {
        if ($versionSize < 1) {
            throw new RuntimeException('Version size must be greater than 0.');
        }

        $this->cryptors = $this->validateAndNormalize($cryptors);

        if (!isset($this->cryptors[$this->currentVersion])) {
            throw new RuntimeException("Current version '{$this->currentVersion}' is not registered.");
        }
    }

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
     * @throws EncryptionException If the version prefix cannot be read or no cryptor matches.
     */
    public function decrypt(
        string $data,
        #[SensitiveParameter]
        string $secret,
        string $context = ''
    ): string {
        if (StringHelper::byteLength($data) < $this->versionSize) {
            throw new EncryptionException('Encrypted data is too short to contain a version identifier.');
        }

        $version = StringHelper::byteSubstring($data, 0, $this->versionSize);
        $cryptor = $this->cryptors[$version]
                ?? throw new EncryptionException(sprintf('Unsupported encrypted data version "0x%s"', bin2hex($version)));

        $payload = StringHelper::byteSubstring($data, $this->versionSize);

        return $cryptor->decrypt($payload, $secret, $context);
    }

    /**
     * Validates the input array, normalises keys to strings,
     * and ensures each version identifier has exactly `$versionSize` bytes.
     *
     * @param array $cryptors Raw input mapping.
     * @throws RuntimeException On validation error.
     * @return array<string, CryptorInterface> Normalised array.
     */
    private function validateAndNormalize(array $cryptors): array
    {
        $normalized = [];
        foreach ($cryptors as $version => $cryptor) {
            $version = (string) $version;

            if (!$cryptor instanceof CryptorInterface) {
                throw new RuntimeException('All cryptors must implement CryptorInterface.');
            }

            if (StringHelper::byteLength($version) !== $this->versionSize) {
                throw new RuntimeException("Version identifier '$version' must be exactly {$this->versionSize} bytes.");
            }

            $normalized[$version] = $cryptor;
        }

        return $normalized;
    }
}
