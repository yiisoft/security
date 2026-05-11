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
     */
    public function getTagSize(): int;
}
