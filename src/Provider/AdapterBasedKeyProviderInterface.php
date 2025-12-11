<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyFactoryException;

/**
 * Interface for adapter-based key provider.
 * 
 * Purpose: Find the right adapter for a specific key TYPE.
 * 
 * This is different from KeyFactory:
 * - KeyFactory: Get adapter by NAME ("halite") for GENERATING keys
 * - AdapterBasedKeyProvider: Get adapter by TYPE SUPPORT ("symmetric_encryption_key") for USING keys
 * 
 * Used by EncryptionAdapters to find the right KeyFactoryAdapter
 * for converting keys to library-specific formats.
 * 
 * Example:
 * ```
 * // EncryptionAdapter needs to convert a key for use
 * $keyFactoryAdapter = $provider->getSupportedAdapter($key->getType());
 * $haliteKey = $keyFactoryAdapter->getAdapterRequiredKey($key, 'halite_key');
 * ```
 */
interface AdapterBasedKeyProviderInterface
{
    /**
     * Gets an adapter that supports the specified key type.
     * 
     * Searches through registered adapters in priority order
     * and returns the first one that supports the key type.
     * 
     * @param string $keyType Key type (e.g., 'symmetric_encryption_key')
     * @return KeyFactoryAdapterInterface Adapter that supports the type
     * @throws KeyFactoryException If no adapter supports the type
     */
    public function getSupportedAdapter(string $keyType): KeyFactoryAdapterInterface;

    /**
     * Checks if any adapter supports the specified key type.
     * 
     * @param string $keyType Key type to check
     * @return bool True if supported by any adapter
     */
    public function supports(string $keyType): bool;

    /**
     * Gets all registered adapters in priority order.
     * 
     * @return array<KeyFactoryAdapterInterface> Adapters
     */
    public function getAllAdapters(): array;
}
