<?php

declare(strict_types=1);

namespace Yiisoft\Security\Tests;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * Invokes a inaccessible method.
     * @param $object
     * @param $method
     * @param array $args
     * @param bool $revoke whether to make method inaccessible after execution
     * @return mixed
     * @throws \ReflectionException
     */
    protected function invokeMethod($object, $method, array $args = [], bool $revoke = true)
    {
        $reflection = new \ReflectionObject($object);
        $method = $reflection->getMethod($method);
        $method->setAccessible(true);
        $result = $method->invokeArgs($object, $args);
        if ($revoke) {
            $method->setAccessible(false);
        }

        return $result;
    }

    /**
     * Sets an inaccessible object property to a designated value.
     * @param $object
     * @param $propertyName
     * @param $value
     * @param bool $revoke whether to make property inaccessible after setting
     * @throws \ReflectionException
     */
    protected function setInaccessibleProperty($object, $propertyName, $value, bool $revoke = true): void
    {
        $class = new \ReflectionClass($object);
        while (!$class->hasProperty($propertyName)) {
            $class = $class->getParentClass();
        }
        $property = $class->getProperty($propertyName);
        $property->setAccessible(true);
        $property->setValue($object, $value);
        if ($revoke) {
            $property->setAccessible(false);
        }
    }


    /**
     * Gets an inaccessible object property.
     * @param $object
     * @param string $propertyName
     * @param bool $revoke whether to make property inaccessible after getting
     * @return mixed
     * @throws \ReflectionException
     */
    protected function getInaccessibleProperty($object, string $propertyName, bool $revoke = true)
    {
        $class = new \ReflectionClass($object);

        while (!$class->hasProperty($propertyName)) {
            $class = $class->getParentClass();
        }

        $property = $class->getProperty($propertyName);
        $property->setAccessible(true);

        $result = $property->getValue($object);
        if ($revoke) {
            $property->setAccessible(false);
        }

        return $result;
    }

    public function assertSameExceptObject($expected, $actual): void
    {
        // assert for all types
        $this->assertEquals($expected, $actual);

        // no more asserts for objects
        if (is_object($expected)) {
            return;
        }

        // asserts same for all types except objects and arrays that can contain objects
        if (!is_array($expected)) {
            $this->assertSame($expected, $actual);
            return;
        }

        // assert same for each element of the array except objects
        foreach ($expected as $key => $value) {
            if (!is_object($value)) {
                $this->assertSame($expected[$key], $actual[$key]);
            } else {
                $this->assertEquals($expected[$key], $actual[$key]);
            }
        }
    }
}
