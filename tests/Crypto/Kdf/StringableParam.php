<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests\Crypto\Kdf;

use SensitiveParameter;
use Stringable;

final class StringableParam implements Stringable
{
    public function __construct(
        #[SensitiveParameter]
        private readonly string $value
    ) {
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
