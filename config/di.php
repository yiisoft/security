<?php

declare(strict_types=1);

use Yiisoft\Definitions\Reference;
use Yiisoft\Definitions\ReferencesArray;

use Yiisoft\Security\Crypt\CryptorInterface;
use Yiisoft\Security\Crypt\EnvelopeCryptor;
use Yiisoft\Security\Crypt\SessionCryptor;
use Yiisoft\Security\Crypt\VersionedCryptor;
use Yiisoft\Security\Crypt\Cipher\OpenSSLGcmCipher;
use Yiisoft\Security\Crypt\Cipher\SodiumCipher;
use Yiisoft\Security\Crypt\Kdf\KdfKey;
use Yiisoft\Security\Crypt\Kdf\KdfPassword;

/** @var array $params */

return [
    CryptorInterface::class => SessionCryptor::class,

    SessionCryptor::class => [
        '__construct()' => [
            'cipher' => Reference::to(OpenSSLGcmCipher::class),
            //'cipher' => Reference::to(SodiumCipher::class),
            'kdf' => Reference::to(KdfKey::class),
            //'kdf' => Reference::to(KdfPassword::class),
        ],
    ],

    EnvelopeCryptor::class => [
        '__construct()' => [
            'cipher' => Reference::to(OpenSSLGcmCipher::class),
            'kdf' => Reference::to(KdfKey::class),
        ],
    ],

    VersionedCryptor::class => [
        '__construct()' => [
            'cryptors' => ReferencesArray::from([
                //chr(0b00000001) => SessionCryptor::class,
                //pack('C', 20) => SessionCryptor::class,
                chr(20) => SessionCryptor::class,
                chr(200) => EnvelopeCryptor::class,
            ]),
            'currentVersion' => chr(200),
            'versionSize' => 1
        ],
    ],
];
