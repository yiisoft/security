<?php

declare(strict_types=1);

namespace Yiisoft\Security\Crypt;

/**
 * Interface for authenticated encryption with associated data (AEAD) ciphers.
 */
interface AeadCipherInterface extends CipherInterface
{
    /**
     * @return int Tag size in bytes.
     *
     * @psalm-return int<1, max>
     */
    public function getTagSize(): int;
}
