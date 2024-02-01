<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter;

use Symfony\Component\Serializer\NameConverter\CamelCaseToSnakeCaseNameConverter;
use Symfony\Component\Serializer\NameConverter\NameConverterInterface;

use function array_keys;
use function array_replace;
use function in_array;
use function str_replace;
use function ucwords;

abstract class AbstractAdapter implements AbstractAdapterInterface
{
    protected string $name;

    protected string $version;

    protected NameConverterInterface $normalizer;

    public function __construct()
    {
        $this->normalizer = new CamelCaseToSnakeCaseNameConverter();
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getVersion(): string
    {
        return $this->version;
    }

    public function setVersion(string $version): void
    {
        $this->version = $version;
    }

    protected function replaceDefaultConfigValues(
        array $defaultConfig,
        array $newConfig,
    ): array {
        $allowed = array_keys($defaultConfig);
        $config = [];
        foreach ($newConfig as $key => $value) {
            if (in_array($key, $allowed)) {
                $config[$key] = $value;
            }
        }
        return array_replace($defaultConfig, $config);
    }

    protected function transformSnakeCaseIntoWord(string $string): string
    {
        return ucwords(str_replace('_', ' ', $string));
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
