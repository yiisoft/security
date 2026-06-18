<p align="center">
    <a href="https://github.com/yiisoft" target="_blank">
        <img src="https://yiisoft.github.io/docs/images/yii_logo.svg" height="100px" alt="Yii">
    </a>
    <h1 align="center">Yii Security</h1>
    <br>
</p>

[![Latest Stable Version](https://poser.pugx.org/yiisoft/security/v)](https://packagist.org/packages/yiisoft/security)
[![Total Downloads](https://poser.pugx.org/yiisoft/security/downloads)](https://packagist.org/packages/yiisoft/security)
[![Build status](https://github.com/yiisoft/security/actions/workflows/build.yml/badge.svg)](https://github.com/yiisoft/security/actions/workflows/build.yml)
[![Code Coverage](https://codecov.io/gh/yiisoft/security/graph/badge.svg?token=PLDTLEJ782)](https://codecov.io/gh/yiisoft/security)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fyiisoft%2Fsecurity%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/yiisoft/security/master)
[![static analysis](https://github.com/yiisoft/security/workflows/static%20analysis/badge.svg)](https://github.com/yiisoft/security/actions?query=workflow%3A%22static+analysis%22)
[![type-coverage](https://shepherd.dev/github/yiisoft/security/coverage.svg)](https://shepherd.dev/github/yiisoft/security)

Security package provides a set of classes to handle common security-related tasks:

- Random values generation
- Password hashing and validation
- Encryption and decryption
- Data tampering prevention
- Masking token length

## Requirements

- PHP 8.2 - 8.5.
- `hash` PHP extension.
- `openssl` PHP extension - optional.
- `sodium` PHP extension - optional.

## Installation

The package could be installed with [Composer](https://getcomposer.org):

```shell
composer require yiisoft/security
```

## General usage

### Random values generation

In order to generate a string that is 42 characters long use:

```php
$randomString = Random::string(42);
```

The following extras are available via PHP directly:

- `random_bytes()` for bytes. Note that output may not be ASCII.
- `random_int()` for integers.

### Password hashing and validation

Working with passwords includes two steps. Saving password hashes:

```php
$hash = (new PasswordHasher())->hash($password);

// save hash to database or another storage
saveHash($hash); 
```

Validating password against the hash:

```php
// obtain hash from database or another storage
$hash = getHash();

$result = (new PasswordHasher())->validate($password, $hash); 
```

### Data tampering prevention

MAC signing could be used in order to prevent data tampering. The `$key` should be present at both sending and receiving
sides. At the sending side:

```php
$signedMessage = (new Mac())->sign($message, $key);

sendMessage($signedMessage);
```

At the receiving side:

```php
$signedMessage = receiveMessage($signedMessage);

try {
    $message = (new Mac())->getMessage($signedMessage, $key);
} catch (\Yiisoft\Security\DataIsTamperedException $e) {
    // data is tampered
}
```

### Masking token length

Masking a token helps to mitigate BREACH attack by randomizing how token outputted on each request.
A random mask applied to the token making the string always unique.

In order to mask a token:

```php
$maskedToken = \Yiisoft\Security\TokenMask::apply($token);
```

In order to get original value from the masked one:

```php
$token = \Yiisoft\Security\TokenMask::remove($maskedToken);
```

### Native PHP functionality

Additionally to this library methods, there is a set of handy native PHP methods.

#### Timing attack resistant string comparison

Comparing strings as usual is not secure when dealing with user inputed passwords or key phrases. Usual string comparison
return as soon as a difference between the strings is found so attacker could efficiently brute-force character by character
going to the next one as soon as response time increases.

There is a special function in PHP that compares strings in a constant time:

```php
hash_equals($expected, $actual);
```

## Crypto module

The `Crypto` module provides a modern, authenticated encryption layer based on `AEAD` ciphers. It provides three built‑in cryptors:

- **`KdfCryptor`** – derives a fresh DEK per message using a KDF.
- **`EnvelopeCryptor`** – wraps a random DEK with a KEK derived from the secret.
- **`VersionedCryptor`** – adds a version prefix to delegate to different cryptors

### Basic usage example

All cryptors implement the same `CryptorInterface`. Inject the desired cryptor and use it as follows:

```php
//via container
use Yiisoft\Security\Crypt\CryptorInterface;

$cryptor = $container->get(CryptorInterface::class);

$secret = 'high-entropy-key-or-password';
$context = 'application-specific-context';

$encrypted = $cryptor->encrypt('secret data', $secret, $context);
$data = $cryptor->decrypt($encrypted, $secret, $context);
```

### KdfCryptor

KDF‑based encryption (single key derived per message, no key wrapping).  
A fresh data encryption key (DEK) is derived from the secret and the provided context using the configured KDF.  
If the configured KDF requires a salt, a random salt is generated for each message and prepended to the ciphertext.

**Output structure:**  
```
kdfSalf (optional) || nonce || encryptedData (with tag)

```

Runtime configuration:
```php
use Yiisoft\Security\Crypto\KdfCryptor;
use Yiisoft\Security\Crypto\Cipher\SodiumAeadCipher;
use Yiisoft\Security\Crypto\Kdf\KdfPasswordArgon2;
use Yiisoft\Security\Crypto\Kdf\KdfKey;

// For high‑entropy keys
$kdf = new KdfKey();
// Or for user‑supplied passwords
$kdf = new KdfPasswordArgon2();

$cipher = new SodiumAeadCipher();
$cryptor = new KdfCryptor($kdf, $cipher);
```

Yii DI configuration:
```php
// /config/di.php
use Yiisoft\DI\Reference;
use Yiisoft\Security\Crypto\KdfCryptor;
use Yiisoft\Security\Crypto\Cipher\SodiumAeadCipher;
use Yiisoft\Security\Crypto\Kdf\KdfKey;

KdfCryptor::class => [
    '__construct()' => [
        'kdf' => Reference::to(KdfKey::class), // replace with KdfPasswordArgon2::class for passwords
        'cipher' => Reference::to(SodiumAeadCipher::class),
    ],
],
```


### EnvelopeCryptor

Envelope encryption (key wrapping) using a KDF to derive a Key Encryption Key (KEK)
and a random Data Encryption Key (DEK). The DEK is wrapped with the KEK and stored
alongside the ciphertext. The DEK is used to encrypt the actual data.

The DEK wrap cipher can be specified separately (e.g., `OpenSSLWrapCipher`); if omitted, the data cipher is used for wrapping as well.

Output structure:
```
kdfSalt || dekNonce || wrappedDEK (with tag) || dataNonce || encryptedData (with tag)
```

Runtime configuration:
```php
use Yiisoft\Security\Crypto\EnvelopeCryptor;
use Yiisoft\Security\Crypto\Cipher\OpenSSLAeadCipher;
use Yiisoft\Security\Crypto\Cipher\OpenSSLWrapCipher;
use Yiisoft\Security\Crypto\Kdf\KdfKey;

$kdf = new KdfKey();
$cipher = new OpenSSLAeadCipher();

// One cipher is used for both data encryption and DEK wrapping
$cryptor = new EnvelopeCryptor($kdf, $cipher);

// Separate cipher is used to wrap the DEK
$kwCipher = new OpenSSLWrapCipher();
$cryptor = new EnvelopeCryptor($kdf, $cipher, $kwCipher);
```

Yii DI configuration:
```php
// /config/di.php
use Yiisoft\DI\Reference;
use Yiisoft\Security\Crypto\EnvelopeCryptor;
use Yiisoft\Security\Crypto\Cipher\OpenSSLAeadCipher;
use Yiisoft\Security\Crypto\Cipher\OpenSSLWrapCipher;
use Yiisoft\Security\Crypto\Kdf\KdfKey;

EnvelopeCryptor::class => [
    '__construct()' => [
        'kdf' => Reference::to(KdfKey::class),
        'cipher' => Reference::to(OpenSSLAeadCipher::class),
        'kwCipher' => Reference::to(OpenSSLWrapCipher::class), // optional, if separate cipher is used to wrap the DEK
    ],
],
```


### VersionedCryptor

Wraps multiple cryptors and adds a fixed‑length version prefix to every ciphertext.

Output structure:
```
version (fixed length) || encrypted payload from underlying cryptor
```

Runtime configuration:
```php
// /config/di.php
use Yiisoft\Security\Crypto\VersionedCryptor;

// Assume $kdfCryptor and $envelopeCryptor are already instantiated
$cryptor = new VersionedCryptor(
    cryptors: [
        chr(0x01) => $kdfCryptor,
        chr(0x96) => $envelopeCryptor,
    ],
    currentVersion: chr(0x01),
);
```

Yii DI configuration:
```php
// /config/di.php
use Yiisoft\DI\ReferencesArray;
use Yiisoft\Security\Crypto\VersionedCryptor;
use Yiisoft\Security\Crypto\KdfCryptor;
use Yiisoft\Security\Crypto\EnvelopeCryptor;

VersionedCryptor::class => [
    '__construct()' => [
        'cryptors' => ReferencesArray::from([
            chr(0x01) => KdfCryptor::class,
            chr(0x96) => EnvelopeCryptor::class,
        ]),
        'currentVersion' => chr(0x01),
        // 'versionSize' => 1, // optional, auto-detected from currentVersion
    ],
],
```

### Configure KDF

The KDF is responsible for deriving cryptographic keys from the provided secret. Choose the appropriate KDF based on the type of secret.

#### KdfKey - for high‑entropy keys
Use this when the secret is already a strong cryptographic key (e.g. a 256‑bit random value). It applies `HKDF` directly.

```php
// /config/di.php
use Yiisoft\Security\Crypt\Kdf\KdfKey;

KdfKey::class => [
    '__construct()' => [
        'algorithm' => 'sha512', // any hash_hmac_algos()
    ],
],
```

#### KdfPasswordPbkdf2 - for low‑entropy passwords
This first applies `PBKDF2` with a configurable iteration count, then `HKDF` to derive the final key.
Follow OWASP recommendations for iteration counts.

```php
// /config/di.php
use Yiisoft\Security\Crypt\Kdf\KdfPassword;

KdfPassword::class => [
    '__construct()' => [
        'algorithm' => 'sha512', // any hash_hmac_algos()
        'iterations' => 700_000,
    ],
],
```

### Configuring AEAD Ciphers

Two backends are available: `OpenSSL` and `Sodium` (libsodium).

#### OpenSSLAeadCipher
Supports `AES‑GCM` family.

```php
// /config/di.php
use Yiisoft\Security\Crypt\Cipher\OpenSSLAeadCipher;

OpenSSLAeadCipher::class => [
    '__construct()' => [
        'cipher' => 'AES-192-GCM',
    ],
],
```

#### SodiumAeadCipher
Supports `AES‑256‑GCM` (hardware accelerated), `ChaCha20‑Poly1305‑IETF`, and `XChaCha20‑Poly1305‑IETF`.
Note: `AES‑256‑GCM` with `Sodium` requires CPU support for AES instructions (`AES‑NI`). Use `ChaCha20‑Poly1305‑IETF` for a safe, non‑hardware‑dependent alternative.

```php
// /config/di.php
use Yiisoft\Security\Crypt\Cipher\SodiumAeadCipher;

SodiumAeadCipher::class => [
    '__construct()' => [
        'cipher' => 'ChaCha20-Poly1305-IETF',
    ],
],
```

## Old cryptor

Note: This is the legacy encryption component based on `CBC` mode + `HMAC`.
For new projects, prefer the AEAD‑based cryptors (`AES‑GCM`, `ChaCha20‑Poly1305`) which provide authenticated encryption in a single step and are less error‑prone.

### Encryption and decryption by password

Encrypting data:

```php
$encryptedData = (new Crypt())->encryptByPassword($data, $password);

// save data to database or another storage
saveData($encryptedData);
```

Decrypting it:

```php
// obtain encrypted data from database or another storage
$encryptedData = getEncryptedData();

$data = (new Crypt())->decryptByPassword($encryptedData, $password);
```

### Encryption and decryption by key

Encrypting data:

```php
$encryptedData = (new Crypt())->encryptByKey($data, $key);

// save data to database or another storage
saveData($encryptedData);
```

Decrypting it:

```php
// obtain encrypted data from database or another storage
$encryptedData = getEncryptedData();

$data = (new Crypt())->decryptByKey($encryptedData, $key);
```

## Documentation

- [Internals](docs/internals.md)

If you need help or have a question, the [Yii Forum](https://forum.yiiframework.com/c/yii-3-0/63) is a good place for that.
You may also check out other [Yii Community Resources](https://www.yiiframework.com/community).

## License

The Yii Security is free software. It is released under the terms of the BSD License.
Please see [`LICENSE`](./LICENSE.md) for more information.

Maintained by [Yii Software](https://www.yiiframework.com/).

## Support the project

[![Open Collective](https://img.shields.io/badge/Open%20Collective-sponsor-7eadf1?logo=open%20collective&logoColor=7eadf1&labelColor=555555)](https://opencollective.com/yiisoft)

## Follow updates

[![Official website](https://img.shields.io/badge/Powered_by-Yii_Framework-green.svg?style=flat)](https://www.yiiframework.com/)
[![Twitter](https://img.shields.io/badge/twitter-follow-1DA1F2?logo=twitter&logoColor=1DA1F2&labelColor=555555?style=flat)](https://twitter.com/yiiframework)
[![Telegram](https://img.shields.io/badge/telegram-join-1DA1F2?style=flat&logo=telegram)](https://t.me/yii3en)
[![Facebook](https://img.shields.io/badge/facebook-join-1DA1F2?style=flat&logo=facebook&logoColor=ffffff)](https://www.facebook.com/groups/yiitalk)
[![Slack](https://img.shields.io/badge/slack-join-1DA1F2?style=flat&logo=slack)](https://yiiframework.com/go/slack)
