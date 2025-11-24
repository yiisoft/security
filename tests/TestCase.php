<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests;

use ReflectionClass;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * Gets an inaccessible object property.
     *
     * @param bool $revoke whether to make property inaccessible after getting
     */
    protected function getInaccessibleProperty(object $object, string $propertyName): mixed
    {
        $class = new ReflectionClass($object);

        while (!$class->hasProperty($propertyName)) {
            $class = $class->getParentClass();
        }

        return $class->getProperty($propertyName)->getValue($object);
    }
}
