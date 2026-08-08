<?php

declare(strict_types=1);

use ShipMonk\ComposerDependencyAnalyser\Config\Configuration;
use ShipMonk\ComposerDependencyAnalyser\Config\ErrorType;

return (new Configuration())
    ->disableComposerAutoloadPathScan()
    ->setFileExtensions(['php'])
    ->addPathToScan(__DIR__ . '/src', isDev: false)
    ->addPathToScan(__DIR__ . '/tests', isDev: true)
    // `MockHelper` is intentionally declared in the `Yiisoft\Security` namespace (not `Yiisoft\Security\Tests`)
    // so it can mock global functions for `Crypt`; it's loaded via `require_once`, not PSR-4 autoloading.
    ->ignoreUnknownClasses(['Yiisoft\Security\MockHelper'])
    // `ext-openssl` is an optional dependency of `Crypt` (see "suggest" in composer.json), checked at
    // runtime via `extension_loaded()`; it's intentionally not in "require".
    ->ignoreErrorsOnExtension('ext-openssl', [ErrorType::SHADOW_DEPENDENCY]);
