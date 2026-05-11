<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Kdf;

use SensitiveParameter;
use Yiisoft\Security\Crypt\KdfInterface;
use function 
    hash_hkdf,
    hash_pbkdf2;

final class KdfPassword implements KdfInterface
{
    public function __construct(
        private string $algorithm = 'sha256',
        private int $iterations = 100_000,
    ) {
    }

    public function createKey(
        #[SensitiveParameter] string $secret,
        int $keySize,
        string $context,
        string $salt,
    ): string
    {
        $key = hash_pbkdf2($this->algorithm, $secret, $salt, $this->iterations, $keySize, true);

        return hash_hkdf($this->algorithm, $key, $keySize, $context);
    }
}
