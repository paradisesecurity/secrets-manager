<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Trait\ConfigurationTrait;

use function current;
use function is_array;
use function reset;

/**
 * Base encryption request implementation with flexible validation.
 * 
 * Supports conditional validation based on operation requirements:
 * - Some operations (encrypt/decrypt) require keys
 * - Some operations (checksum) can work without keys
 * - File operations may or may not require output files
 * 
 * Validation is controlled by flags set during construction.
 * 
 * Encapsulates all parameters needed for encryption/decryption operations.
 * Implements Command pattern for flexible parameter passing.
 * 
 * Features:
 * - Fluent interface for configuration
 * - Type-safe parameter handling
 * - Default values for optional parameters
 * - Support for both single keys and key arrays
 * 
 * Usage:
 * ```
 * $request = new EncryptionRequest($key)
 *     ->setAsymmetric(true)
 *     ->setEncoding('base64')
 *     ->setAdditionalData('metadata');
 * ```
 */
class EncryptionRequest implements EncryptionRequestInterface
{
    use ConfigurationTrait;

    /** @var array<KeyInterface> */
    protected array $keys = [];

    protected ?string $encoding = null;
    protected ?bool $chooseEncoder = null;
    protected bool $decode = false;
    protected string $additionalData = '';
    protected bool $asymmetric = false;
    protected ?string $mac = null;
    protected ?string $signature = null;
    protected ?string $version = null;

    /** @var array<string, mixed> */
    protected array $configuration = [];

    // Validation requirements
    protected bool $requiresKeys = true;

    private array $default = [
        EncryptionRequestInterface::ENCODING,
        EncryptionRequestInterface::CHOOSE_ENCODER,
        EncryptionRequestInterface::DECODE,
        EncryptionRequestInterface::ADDITIONAL_DATA,
        EncryptionRequestInterface::MAC,
        EncryptionRequestInterface::VERSION,
        EncryptionRequestInterface::ASYMMETRIC,
        EncryptionRequestInterface::SIGNATURE
    ];

    /**
     * @param KeyInterface|array<KeyInterface>|array<empty> $keys Single key, array of keys, or empty array
     * @param array<string, mixed> $config Initial configuration
     */
    public function __construct(
        KeyInterface|array $keys,
        array $config = [],
    ) {
        // Check if keys are explicitly not required
        $this->requiresKeys = $config[self::REQUIRES_KEYS] ?? true;

        $this->initializeKeys($keys);
        $this->applyConfiguration($config);
    }

    public function getKeys(): array
    {
        return $this->keys;
    }

    public function getKey(): KeyInterface
    {
        if (empty($this->keys)) {
            throw new \RuntimeException('No keys available in request. This operation requires at least one key.');
        }

        reset($this->keys);
        return current($this->keys);
    }

    public function hasKeys(): bool
    {
        return !empty($this->keys);
    }

    /**
     * Requires that at least one key exists.
     * Use this in adapters for operations that must have keys.
     */
    public function requiresKeys(): bool
    {
        return $this->requiresKeys;
    }

    public function getEncoding(): ?string
    {
        return $this->encoding;
    }

    public function setEncoding(?string $encoding): static
    {
        $this->encoding = $encoding;
        return $this;
    }

    public function chooseEncoder(): ?bool
    {
        return $this->chooseEncoder;
    }

    public function setChooseEncoder(?bool $choose): static
    {
        $this->chooseEncoder = $choose;
        return $this;
    }

    public function shouldDecode(): bool
    {
        return $this->decode;
    }

    public function setDecode(bool $decode): static
    {
        $this->decode = $decode;
        return $this;
    }

    public function getAdditionalData(): string
    {
        return $this->additionalData;
    }

    public function setAdditionalData(?string $data): static
    {
        $this->additionalData = $data ?? '';
        return $this;
    }

    public function isAsymmetric(): bool
    {
        return $this->asymmetric;
    }

    public function setAsymmetric(bool $asymmetric): static
    {
        $this->asymmetric = $asymmetric;
        return $this;
    }

    public function getVersion(): ?string
    {
        return $this->version;
    }

    public function setVersion(?string $version): static
    {
        $this->version = $version;
        return $this;
    }

    public function getMac(): ?string
    {
        return $this->mac;
    }

    public function setMac(?string $mac): static
    {
        $this->mac = $mac;
        return $this;
    }

    public function getSignature(): ?string
    {
        return $this->signature;
    }

    public function setSignature(?string $signature): static
    {
        $this->signature = $signature;
        return $this;
    }

    public function getConfiguration(): array
    {
        return [
            self::ENCODING => $this->encoding,
            self::CHOOSE_ENCODER => $this->chooseEncoder,
            self::DECODE => $this->decode,
            self::ADDITIONAL_DATA => $this->additionalData,
            self::ASYMMETRIC => $this->asymmetric,
            self::MAC => $this->mac,
            self::SIGNATURE => $this->signature,
            self::VERSION => $this->version,
        ] + $this->configuration;
    }

    public function setConfiguration(string $key, mixed $value): static
    {
        // Handle known configuration keys
        $setter = match ($key) {
            self::ENCODING => fn($v) => $this->setEncoding($v),
            self::CHOOSE_ENCODER => fn($v) => $this->setChooseEncoder($v),
            self::DECODE => fn($v) => $this->setDecode($v),
            self::ADDITIONAL_DATA => fn($v) => $this->setAdditionalData($v),
            self::ASYMMETRIC => fn($v) => $this->setAsymmetric($v),
            self::MAC => fn($v) => $this->setMac($v),
            self::SIGNATURE => fn($v) => $this->setSignature($v),
            self::VERSION => fn($v) => $this->setVersion($v),
            default => null,
        };

        if ($setter !== null) {
            $setter($value);
        } else {
            // Store unknown configuration for adapter-specific use
            $this->configuration[$key] = $value;
            // Legacy Trait Behavior
            $this->options[$key] = $value;
        }

        return $this;
    }

    /**
     * Initializes keys from constructor parameter.
     */
    protected function initializeKeys(KeyInterface|array $keys): void
    {
        if (!is_array($keys)) {
            $keys = [$keys];
        }

        foreach ($keys as $key) {
            if ($key instanceof KeyInterface) {
                $this->keys[] = $key;
            }
        }

        // Only validate if keys are required for this operation
        if ($this->requiresKeys && empty($this->keys)) {
            throw new \InvalidArgumentException(
                'At least one valid KeyInterface must be provided for this operation'
            );
        }
    }

    /**
     * Applies configuration from array.
     */
    protected function applyConfiguration(array $config): void
    {
        foreach ($config as $key => $value) {
            // Skip validation flags - they're not part of normal config
            if ($key === self::REQUIRES_KEYS || $key === self::REQUIRES_OUTPUT_FILE) {
                continue;
            }

            if (is_string($key)) {
                $this->setConfiguration($key, $value);
            }
        }
    }

    // Legacy: Use shouldDecode
    public function decode(): bool
    {
        return $this->decode;
    }
}
