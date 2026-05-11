<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt\Kdf;

use SensitiveParameter;
use Yiisoft\Security\Crypt\KdfInterface;
use function 
    hash_hkdf;

final readonly class KdfKey implements KdfInterface
{
    public function __construct(
        private string $algorithm = 'sha256',
    ) {
    }

    public function createKey(
        #[SensitiveParameter]
        string $secret,
        int $keySize,
        string $context,
        string $salt,
    ): string
    {
        return hash_hkdf($this->algorithm, $secret, $keySize, $context, $salt);
    }
}
