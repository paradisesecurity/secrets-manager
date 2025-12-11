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

/**
 * Abstract base class for all adapters in the SecretsManager.
 * 
 * Provides common functionality for adapter identification, versioning,
 * and utility methods for string transformations and configuration management.
 * 
 * Adapters represent different implementations of specific functionality:
 * - EncryptionAdapterInterface: Different encryption libraries
 * - KeyFactoryAdapterInterface: Different key generation mechanisms
 * - VaultAdapterInterface: Different secret storage formats
 * 
 * Note: FilesystemAdapterInterface is intentionally independent and doesn't
 * extend this class, as it represents a different abstraction layer (storage
 * backend vs. operational adapter).
 */
abstract class AbstractAdapter implements AbstractAdapterInterface
{
    protected string $name;

    protected string $version;

    private NameConverterInterface $normalizer;

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

    /**
     * Merges new configuration values with defaults.
     * 
     * Only allows keys that exist in the default configuration,
     * preventing invalid configuration keys.
     * 
     * @param array $defaultConfig Default configuration values
     * @param array $newConfig User-provided configuration
     * @return array Merged configuration
     */
    protected function replaceDefaultConfigValues(
        array $defaultConfig,
        array $newConfig,
    ): array {
        $allowed = array_keys($defaultConfig);
        $filtered = [];

        foreach ($newConfig as $key => $value) {
            if (in_array($key, $allowed, true)) {
                $filtered[$key] = $value;
            }
        }

        return array_replace($defaultConfig, $filtered);
    }

    /**
     * Converts snake_case string to human-readable format.
     * 
     * Example: "symmetric_encryption_key" -> "Symmetric Encryption Key"
     * 
     * @param string $string Snake case string
     * @return string Human-readable string
     */
    protected function transformSnakeCaseIntoWord(string $string): string
    {
        return ucwords(str_replace('_', ' ', $string));
    }

    /**
     * Converts snake_case to camelCase.
     * 
     * Example: "encryption_key" -> "encryptionKey"
     * 
     * @param string $string Snake case string
     * @return string Camel case string
     */
    protected function convertSnakeCaseToCamelCase(string $string): string
    {
        return $this->normalizer->denormalize($string);
    }

    /**
     * Converts camelCase to snake_case.
     * 
     * Example: "encryptionKey" -> "encryption_key"
     * 
     * @param string $string Camel case string
     * @return string Snake case string
     */
    protected function convertCamelCaseToSnakeCase(string $string): string
    {
        return $this->normalizer->normalize($string);
    }
}
