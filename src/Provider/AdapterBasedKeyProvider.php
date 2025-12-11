<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyFactoryException;
use ParadiseSecurity\Component\ServiceRegistry\Registry\PrioritizedServiceRegistryInterface;

/**
 * Provides key factory adapters based on key type support.
 * 
 * Design pattern: Chain of Responsibility
 * - Tries adapters in priority order
 * - Returns first adapter that supports the key type
 * 
 * Purpose:
 * Used by EncryptionAdapters to find the right KeyFactoryAdapter
 * for converting keys between formats.
 * 
 * Example workflow:
 * 1. EncryptionAdapter receives a Key object
 * 2. Asks provider for adapter that supports key's type
 * 3. Uses adapter to convert key to library-specific format
 * 4. Performs encryption operation
 */
final class AdapterBasedKeyProvider implements AdapterBasedKeyProviderInterface
{
    public function __construct(
        private PrioritizedServiceRegistryInterface $adapterRegistry
    ) {
    }

    public function getSupportedAdapter(string $keyType): KeyFactoryAdapterInterface
    {
        foreach ($this->adapterRegistry->all() as $adapter) {
            if ($adapter->supports($keyType)) {
                return $adapter;
            }
        }

        throw KeyFactoryException::unsupportedKeyType(
            $keyType,
            $this->getSupportedKeyTypes()
        );
    }

    public function supports(string $keyType): bool
    {
        foreach ($this->adapterRegistry->all() as $adapter) {
            if ($adapter->supports($keyType)) {
                return true;
            }
        }

        return false;
    }

    public function getAllAdapters(): array
    {
        return array_values($this->adapterRegistry->all());
    }

    /**
     * Gets all key types supported by registered adapters.
     * 
     * @return array<string> Supported key types
     */
    private function getSupportedKeyTypes(): array
    {
        $types = [];

        foreach ($this->adapterRegistry->all() as $adapter) {
            $types = array_merge($types, $adapter->getSupportedKeyTypes());
        }

        return array_unique($types);
    }
}
