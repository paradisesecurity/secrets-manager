<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Symfony\Component\Serializer\NameConverter\CamelCaseToSnakeCaseNameConverter;
use Symfony\Component\Serializer\NameConverter\NameConverterInterface;

use function class_exists;

final class Setup
{
    protected NameConverterInterface $normalizer;

    public function __construct()
    {
        $this->normalizer = new CamelCaseToSnakeCaseNameConverter(null, false);
    }

    public function get(string $class): SetupInterface
    {
        $class = $class . '_setup';
        $className = $this->convertSnakeCaseToCamelCase($class);
        $className = __NAMESPACE__ . '\\' . $className;

        if (class_exists($className)) {
            return new $className();
        }

        throw new \LogicException("Unable to load class: $className");
    }

    protected function convertSnakeCaseToCamelCase(string $string): string
    {
        return $this->normalizer->denormalize($string);
    }

    protected function convertCamelCaseToSnakeCase(string $string): string
    {
        return $this->normalizer->normalize($string);
    }
}
