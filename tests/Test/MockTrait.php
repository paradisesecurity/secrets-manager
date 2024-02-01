<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test;

use ReflectionClass;
use ReflectionMethod;

use function array_search;

trait MockTrait
{
    protected function getClassMethods(string $class): array
    {
        $reflection = new ReflectionClass($class);
        $methods = [];
        foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->getDeclaringClass()->getName() === $reflection->getName()) {
                $methods[] = $method->getName();
            }
        }
        $index = array_search('__construct', $methods, true);
        if ($index !== false) {
            unset($methods[$index]);
        }
        return $methods;
    }
}
