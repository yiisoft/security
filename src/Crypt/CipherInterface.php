<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

use SensitiveParameter;

interface CipherInterface
{
    public function encrypt(
        string $data,
        #[SensitiveParameter] string $key,
        string $nounce,
    ): string;

    public function decrypt(
        string $date,
        #[SensitiveParameter] string $key,
        string $nounce,
    ): string;

    public function getNounceSize(): int;

    public function getKeySize(): int;
}
