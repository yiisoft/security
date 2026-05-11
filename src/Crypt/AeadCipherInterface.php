<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

interface AeadCipherInterface extends CipherInterface
{
    public function getTagSize(): int;
}
