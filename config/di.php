<?php

declare(strict_types=1);

use Yiisoft\Definitions\Reference;
use Yiisoft\Definitions\ReferencesArray;

use Yiisoft\Security\CryptorInterface;
use Yiisoft\Security\EnvelopeCryptor;
use Yiisoft\Security\SessionCryptor;
use Yiisoft\Security\VersionedCryptor;
use Yiisoft\Security\Cipher\OpenSSLCipher;
use Yiisoft\Security\Cipher\SodiumCipher;
use Yiisoft\Security\Kdf\KdfKey;
use Yiisoft\Security\Kdf\KdfPassword;

/** @var array $params */

return [
    CryptorInterface::class => SessionCryptor::class,

    SessionCryptor::class => [
        '__construct()' => [
            'cipher' => Reference::to(OpenSSLCipher::class),
            //'cipher' => Reference::to(SodiumCipher::class),
            'kdf' => Reference::to(KdfKey::class),
            //'kdf' => Reference::to(KdfPassword::class),
        ],
    ],

    EnvelopeCryptor::class => [
        '__construct()' => [
            'cipher' => Reference::to(OpenSSLCipher::class),
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
