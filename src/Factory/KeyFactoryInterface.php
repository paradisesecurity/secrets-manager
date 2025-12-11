<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Factory;

use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyFactoryException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyTypeConstants;
use ParagonIE\HiddenString\HiddenString;

/**
 * Interface for key factory.
 * 
 * The KeyFactory is responsible for:
 * - Managing KeyFactoryAdapter instances by name
 * - Generating new cryptographic keys
 * - Converting between key formats
 * - Extracting raw key material
 * 
 * Uses Strategy pattern: Different adapters for different crypto libraries.
 */
interface KeyFactoryInterface
{
    // Reference the central values - defined once, used everywhere
    public const ASYMMETRIC_ENCRYPTION_KEY_PAIR = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_KEY_PAIR;
    public const ASYMMETRIC_ENCRYPTION_PUBLIC_KEY = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY;
    public const ASYMMETRIC_ENCRYPTION_SECRET_KEY = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_SECRET_KEY;
    public const ASYMMETRIC_SIGNATURE_KEY_PAIR = KeyTypeConstants::ASYMMETRIC_SIGNATURE_KEY_PAIR;
    public const ASYMMETRIC_SIGNATURE_PUBLIC_KEY = KeyTypeConstants::ASYMMETRIC_SIGNATURE_PUBLIC_KEY;
    public const ASYMMETRIC_SIGNATURE_SECRET_KEY = KeyTypeConstants::ASYMMETRIC_SIGNATURE_SECRET_KEY;
    public const SYMMETRIC_AUTHENTICATION_KEY = KeyTypeConstants::SYMMETRIC_AUTHENTICATION_KEY;
    public const SYMMETRIC_ENCRYPTION_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_KEY;
    public const SYMMETRIC_ENCRYPTION_PUBLIC_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_PUBLIC_KEY;
    public const SYMMETRIC_ENCRYPTION_SECRET_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_SECRET_KEY;
    public const SYMMETRIC_SIGNATURE_PUBLIC_KEY = KeyTypeConstants::SYMMETRIC_SIGNATURE_PUBLIC_KEY;
    public const SYMMETRIC_SIGNATURE_SECRET_KEY = KeyTypeConstants::SYMMETRIC_SIGNATURE_SECRET_KEY;
    public const UNKNOWN_KEY = KeyTypeConstants::UNKNOWN_KEY;
    public const HEX_KEY = KeyTypeConstants::HEX_KEY;
    public const RAW_KEY = KeyTypeConstants::RAW_KEY;

    /**
     * Gets a key factory adapter by name.
     * 
     * @param string $adapterName Adapter name (e.g., 'halite', 'sodium')
     * @return KeyFactoryAdapterInterface The adapter
     * @throws KeyFactoryException If adapter not found
     */
    public function getAdapter(string $adapter): KeyFactoryAdapterInterface;

    /**
     * Checks if an adapter is registered.
     * 
     * @param string $adapterName Adapter name
     * @return bool True if registered
     */
    public function hasAdapter(string $adapterName): bool;

    /**
     * Gets all registered adapter names.
     * 
     * @return array<string> Adapter names
     */
    public function getAdapterNames(): array;

    /**
     * Generates a new cryptographic key.
     * 
     * @param KeyConfigInterface $config Key configuration (type, parameters, etc.)
     * @param string $adapterName Adapter name to use for generation
     * @return KeyInterface Generated key
     * @throws KeyFactoryException If generation fails
     */
    public function generateKey(KeyConfigInterface $config, string $adapterName): KeyInterface;

    /**
     * Builds a Key object from raw hex key data.
     * 
     * Used for importing keys from external sources.
     * 
     * @param string $hex Hex-encoded key data
     * @param string $type Key type
     * @param string $adapterName Adapter name
     * @param string $version Key version
     * @return KeyInterface Key object
     */
    public function buildKeyFromRawKeyData(
        string $hex,
        string $type,
        string $adapterName,
        string $version
    ): KeyInterface;

    /**
     * Extracts raw key material from a Key object.
     * 
     * Returns the raw binary key data suitable for cryptographic operations.
     * 
     * @param KeyInterface $key Key to extract from
     * @return HiddenString Raw key material (empty if not supported)
     */
    public function getRawKeyMaterial(KeyInterface $key): HiddenString;

    /**
     * Splits a key pair into individual public and secret keys.
     * 
     * @param KeyInterface $keyPair Key pair to split
     * @return array{KeyInterface, KeyInterface} [publicKey, secretKey]
     * @throws KeyFactoryException If key is not a key pair or splitting fails
     */
    public function splitKeyPair(KeyInterface $keyPair): array;
}
