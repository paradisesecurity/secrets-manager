<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Trait;

use function array_key_exists;
use function in_array;
use function is_null;
use function lcfirst;
use function preg_replace_callback;
use function property_exists;
use function strtoupper;

/**
 * Configuration management trait.
 * 
 * Provides dynamic configuration handling with support for:
 * - Property mapping (snake_case keys to camelCase properties)
 * - Default/predefined configuration keys
 * - Custom/arbitrary configuration options
 * - Backward compatibility with legacy code
 * 
 * Best Practices:
 * - Keep traits focused on single responsibility [web:222][web:231]
 * - Use for code reuse across unrelated classes [web:223][web:226]
 * - Document required properties in PHPDoc
 * 
 * Required Properties in Using Class:
 * - array $default: List of predefined configuration keys
 * - mixed properties matching keys in $default (optional)
 * 
 * Example:
 * ```
 * class MyRequest
 * {
 *     use ConfigurationTrait;
 * 
 *     private array $default = ['encoding', 'version'];
 *     private ?string $encoding = null;
 *     private ?string $version = null;
 * 
 *     public function __construct(array $config = [])
 *     {
 *         $this->applyConfiguration($config);
 *     }
 * }
 * ```
 * 
 * @deprecated Consider migrating to explicit configuration management
 *             This trait is maintained for backward compatibility
 */
trait ConfigurationTrait
{
    /**
     * Storage for custom/arbitrary configuration options.
     * 
     * @var array<string, mixed>
     */
    protected array $options = [];

    /**
     * Checks if a custom option exists.
     * 
     * Note: This only checks custom options, not mapped properties.
     * Use hasConfig() to check both.
     * 
     * @param string $key Option key
     * @return bool True if option exists
     */
    public function hasOption(string $key): bool
    {
        return array_key_exists($key, $this->options);
    }

    /**
     * Gets a custom option value.
     * 
     * Note: This only retrieves custom options, not mapped properties.
     * Use getConfig() to retrieve both.
     * 
     * @param string $key Option key
     * @return mixed Option value or null if not found
     */
    public function getOption(string $key): mixed
    {
        return $this->options[$key] ?? null;
    }

    /**
     * Gets all custom options.
     * 
     * @return array<string, mixed> Custom options array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Adds or updates a custom option.
     * 
     * If the key is in $default, updates the mapped property.
     * Otherwise, stores in custom options.
     * 
     * @param string $key Option key
     * @param mixed $value Option value
     * @return static Fluent interface
     */
    public function addOption(string $key, mixed $value): static
    {
        $this->processConfiguration($key, $value);
        return $this;
    }

    /**
     * Adds or updates multiple options at once.
     * 
     * @param array<string, mixed> $options Options to add
     * @return static Fluent interface
     */
    public function addOptions(array $options): static
    {
        foreach ($options as $key => $value) {
            if (is_string($key)) {
                $this->processConfiguration($key, $value);
            }
        }
        return $this;
    }

    /**
     * Checks if a configuration exists (either mapped property or custom option).
     * 
     * @param string $key Configuration key
     * @return bool True if configuration exists
     */
    public function hasConfig(string $key): bool
    {
        if ($this->isMappedProperty($key)) {
            $variableName = $this->getVariableName($key);
            return property_exists($this, $variableName);
        }

        return $this->hasOption($key);
    }

    /**
     * Gets a configuration value (from mapped property or custom option).
     * 
     * Checks mapped properties first, then falls back to custom options.
     * 
     * @param string $key Configuration key
     * @return mixed Configuration value or null if not found
     */
    public function getConfig(string $key): mixed
    {
        if ($this->isMappedProperty($key)) {
            $variableName = $this->getVariableName($key);
            if (property_exists($this, $variableName)) {
                return $this->$variableName;
            }
        }

        return $this->getOption($key);
    }

    /**
     * Gets all configuration (both mapped properties and custom options).
     * 
     * Mapped properties take precedence over custom options with the same key.
     * 
     * @return array<string, mixed> Complete configuration array
     */
    public function getConfiguration(): array
    {
        $options = $this->options;

        // Add default/mapped properties
        if (property_exists($this, 'default') && is_array($this->default)) {
            foreach ($this->default as $key) {
                $value = $this->getConfig($key);
                if (!is_null($value)) {
                    $options[$key] = $value;
                }
            }
        }

        return $options;
    }

    /**
     * Sets a configuration value.
     * 
     * Alias for addOption() for consistency with new EncryptionRequest API.
     * 
     * @param string $key Configuration key
     * @param mixed $value Configuration value
     * @return static Fluent interface
     */
    public function setConfiguration(string $key, mixed $value): static
    {
        return $this->addOption($key, $value);
    }

    /**
     * Applies multiple configuration values at once.
     * 
     * Helper method for constructor initialization.
     * 
     * @param array<string, mixed> $config Configuration array
     * @return static Fluent interface
     */
    protected function applyLegacyConfiguration(array $config): static
    {
        return $this->addOptions($config);
    }

    /**
     * Converts snake_case configuration key to camelCase property name.
     * 
     * Examples:
     * - 'encoding' -> 'encoding'
     * - 'additional_data' -> 'additionalData'
     * - 'choose_encoder' -> 'chooseEncoder'
     * 
     * @param string $key Configuration key in snake_case
     * @return string Property name in camelCase
     */
    protected function getVariableName(string $key): string
    {
        return lcfirst(
            preg_replace_callback(
                '/(^|_|\.)+(.)/',
                fn($match) => ('.' === $match[1] ? '_' : '') . strtoupper($match[2]),
                $key
            )
        );
    }

    /**
     * Processes a configuration key-value pair.
     * 
     * If the key is a mapped property (in $default), sets the property.
     * Otherwise, stores in custom options.
     * 
     * @param string $key Configuration key
     * @param mixed $value Configuration value
     * @return void
     */
    protected function processConfiguration(string $key, mixed $value): void
    {
        if ($this->isMappedProperty($key)) {
            $variableName = $this->getVariableName($key);
            if (property_exists($this, $variableName)) {
                $this->$variableName = $value;
                return;
            }
        }

        $this->options[$key] = $value;
    }

    /**
     * Checks if a key is a mapped property (defined in $default array).
     * 
     * @param string $key Configuration key
     * @return bool True if key is mapped to a property
     */
    private function isMappedProperty(string $key): bool
    {
        if (!property_exists($this, 'default')) {
            return false;
        }

        if (!is_array($this->default)) {
            return false;
        }

        return in_array($key, $this->default, true);
    }
}
