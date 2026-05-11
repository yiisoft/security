<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;

interface KdfInterface
{
    public function createKey(
        #[SensitiveParameter]
        string $secret,
        int $keySize,
        string $context,
        string $salt,
    ): string;
}
