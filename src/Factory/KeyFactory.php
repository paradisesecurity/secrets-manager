<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Factory;

use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyFactoryException;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistryInterface;
use ParagonIE\HiddenString\HiddenString;

/**
 * Key factory for generating and managing cryptographic keys.
 * 
 * Purpose: Centralized key generation across different crypto libraries.
 * 
 * Responsibilities:
 * - Manages adapters by NAME (e.g., "halite", "sodium")
 * - Delegates key generation to appropriate adapter
 * - Provides key format conversions
 * 
 * vs AdapterBasedKeyProvider:
 * - KeyFactory: Indexed by adapter NAME, used for generating NEW keys
 * - AdapterBasedKeyProvider: Indexed by key TYPE support, used for OPERATIONS on existing keys
 */
final class KeyFactory implements KeyFactoryInterface
{
    public function __construct(
        private ServiceRegistryInterface $adapterRegistry
    ) {
    }

    public function getAdapter(string $adapterName): KeyFactoryAdapterInterface
    {
        if (!$this->hasAdapter($adapterName)) {
            throw KeyFactoryException::adapterNotFound($adapterName, $this->getAdapterNames());
        }

        return $this->adapterRegistry->get($adapterName);
    }

    public function hasAdapter(string $adapterName): bool
    {
        return $this->adapterRegistry->has($adapterName);
    }

    public function getAdapterNames(): array
    {
        return array_keys($this->adapterRegistry->all());
    }

    public function generateKey(KeyConfigInterface $config, string $adapterName): KeyInterface
    {
        $adapter = $this->getAdapter($adapterName);

        try {
            return $adapter->generateKey($config);
        } catch (\Exception $exception) {
            throw KeyFactoryException::generationFailed(
                $config->getType(),
                $adapterName,
                $exception
            );
        }
    }

    public function buildKeyFromRawKeyData(
        string $hex,
        string $type,
        string $adapterName,
        string $version
    ): KeyInterface {
        return new Key(
            new HiddenString($hex),
            $type,
            $adapterName,
            $version
        );
    }

    public function getRawKeyMaterial(KeyInterface $key): HiddenString
    {
        $adapterName = $key->getAdapter();

        if (!$this->hasAdapter($adapterName)) {
            return new HiddenString('');
        }

        $adapter = $this->getAdapter($adapterName);

        if (!$adapter->supports(self::RAW_KEY)) {
            return new HiddenString('');
        }

        try {
            return $adapter->getAdapterRequiredKey($key, self::RAW_KEY);
        } catch (\Exception) {
            return new HiddenString('');
        }
    }

    public function splitKeyPair(KeyInterface $keyPair): array
    {
        $adapterName = $keyPair->getAdapter();
        $adapter = $this->getAdapter($adapterName);

        if (!$adapter->isKeyPair($keyPair->getType())) {
            throw KeyFactoryException::notAKeyPair($keyPair->getType());
        }

        try {
            $adapterKeyType = $adapter->getAdapterSpecificKeyType($keyPair);
            return $adapter->splitKeyPair($keyPair, $adapterKeyType);
        } catch (\Exception $exception) {
            throw KeyFactoryException::splitFailed($keyPair->getType(), $exception);
        }
    }
}
