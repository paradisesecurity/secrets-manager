<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory;

use ParadiseSecurity\Component\SecretsManager\Adapter\AbstractAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

/**
 * Interface for key factory adapters.
 * 
 * Key factory adapters provide abstraction over different cryptographic
 * key generation and manipulation libraries. They handle:
 * - Generating new cryptographic keys
 * - Converting between key formats (hex, raw, library-specific)
 * - Splitting key pairs into individual keys
 * - Importing/exporting keys
 * 
 * Implementations wrap specific libraries like Halite, Sodium, OpenSSL, etc.
 * 
 * @see AbstractKeyFactoryAdapter for base implementation
 * @see HaliteKeyFactoryAdapter for Halite library implementation
 */
interface KeyFactoryAdapterInterface extends AbstractAdapterInterface
{
    /**
     * Gets the adapter-specific key type identifier.
     * 
     * Returns the internal key type used by this adapter (e.g., 'halite_key', 'sodium_key').
     * 
     * @param KeyInterface $key The key to get type for
     * @return string Adapter-specific key type
     */
    public function getAdapterSpecificKeyType(KeyInterface $key): string;

    /**
     * Gets all key types supported by this adapter.
     * 
     * @return array<string> List of supported key type identifiers
     */
    public function getSupportedKeyTypes(): array;

    /**
     * Checks if adapter supports a specific key type.
     * 
     * @param string $keyType Key type to check
     * @return bool True if supported, false otherwise
     */
    public function supports(string $keyType): bool;

    /**
     * Gets parent key types for a given key type.
     * 
     * For example, an asymmetric_encryption_public_key has
     * asymmetric_encryption_key_pair as its parent.
     * 
     * @param string $type Child key type
     * @return array<string> Parent key types
     */
    public function getParentKey(string $type): array;

    /**
     * Gets child key types for a key pair.
     * 
     * For example, an asymmetric_encryption_key_pair has
     * asymmetric_encryption_public_key and asymmetric_encryption_secret_key as children.
     * 
     * @param string $type Key pair type
     * @return array<string> Child key types
     */
    public function getChildKeys(string $type): array;

    /**
     * Converts a generic Key to adapter-specific key format.
     * 
     * Takes a KeyInterface and converts it to the format required by
     * the underlying encryption library (e.g., Halite\Key, Sodium resource).
     * 
     * @param KeyInterface $key Generic key
     * @param string $type Target key type
     * @return mixed Adapter-specific key object
     * @throws UnableToLoadKeyException If conversion fails
     */
    public function getAdapterRequiredKey(KeyInterface $key, string $type): mixed;

    /**
     * Splits a key pair into individual public and secret keys.
     * 
     * @param KeyInterface $key Key pair to split
     * @param string $keyType Target adapter key type
     * @return array<KeyInterface> Array containing public and secret keys
     * @throws UnableToLoadKeyException If splitting fails
     */
    public function splitKeyPair(KeyInterface $key, string $keyType): array;

    /**
     * Checks if a key type represents a key pair.
     * 
     * @param string $type Key type to check
     * @return bool True if key pair, false otherwise
     */
    public function isKeyPair(string $type): bool;

    /**
     * Checks if a key type represents a public key.
     * 
     * @param string $type Key type to check
     * @return bool True if public key, false otherwise
     */
    public function isPublicKey(string $type): bool;

    /**
     * Checks if a key type represents a secret/private key.
     * 
     * @param string $type Key type to check
     * @return bool True if secret key, false otherwise
     */
    public function isSecretKey(string $type): bool;

    /**
     * Gets default configuration for key generation.
     * 
     * @param string|null $version Library version (null for current)
     * @return array Default configuration values
     */
    public function getDefaultConfig(?string $version = null): array;

    /**
     * Generates a new cryptographic key based on configuration.
     * 
     * @param KeyConfigInterface $config Key generation configuration
     * @return KeyInterface Generated key
     * @throws UnableToGenerateKeyException If generation fails
     */
    public function generateKey(KeyConfigInterface $config): KeyInterface;
}
