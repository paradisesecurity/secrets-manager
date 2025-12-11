<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

/**
 * Configuration for master key loading.
 * 
 * Defines which keys to load and from which loader.
 */
final class MasterKeyConfiguration
{
    /** @var array<string> Required key names */
    private array $requiredKeys;

    /**
     * @param string $loaderName Name of loader to use
     * @param array<string>|null $requiredKeys Keys to load (null = all default keys)
     */
    public function __construct(
        private string $loaderName,
        ?array $requiredKeys = null
    ) {
        $this->requiredKeys = $requiredKeys ?? $this->getDefaultRequiredKeys();
    }

    /**
     * Gets the loader name.
     */
    public function getLoaderName(): string
    {
        return $this->loaderName;
    }

    /**
     * Gets required key names.
     * 
     * @return array<string> Key names
     */
    public function getRequiredKeys(): array
    {
        return $this->requiredKeys;
    }

    /**
     * Checks if a key is required.
     */
    public function isKeyRequired(string $keyName): bool
    {
        return in_array($keyName, $this->requiredKeys, true);
    }

    /**
     * Gets default required keys.
     * 
     * @return array<string> Default key names
     */
    private function getDefaultRequiredKeys(): array
    {
        return [
            MasterKeyProviderInterface::MASTER_SYMMETRIC_ENCRYPTION_KEY,
            MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR,
            MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY,
            MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
        ];
    }

    /**
     * Creates configuration for specific loader.
     */
    public static function forLoader(string $loaderName): self
    {
        return new self($loaderName);
    }

    /**
     * Creates configuration with custom keys.
     */
    public static function withKeys(string $loaderName, array $keyNames): self
    {
        return new self($loaderName, $keyNames);
    }
}
