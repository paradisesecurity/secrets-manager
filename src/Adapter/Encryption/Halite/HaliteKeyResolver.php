<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite;

use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\Halite\Key as HaliteKey;
use ParagonIE\Halite\KeyPair as HaliteKeyPair;

use function in_array;

/**
 * Resolves and converts keys to Halite-specific key types.
 * Handles key pair splitting and type matching.
 */
final class HaliteKeyResolver
{
    public function __construct(
        private KeyFactoryAdapterInterface $keyFactoryAdapter,
        private string $requiredKeyType,
    ) {
    }

    /**
     * Determines the correct Halite key instance from available keys.
     */
    public function resolveKey(array $keys, array $allowedTypes): HaliteKey|HaliteKeyPair
    {
        try {
            return $this->findKeyOrThrow($keys, $allowedTypes);
        } catch (UnableToEncryptMessageException) {
            // Try splitting key pairs
            $expandedKeys = $this->expandKeyPairs($keys);
            return $this->findKeyOrThrow($expandedKeys, $allowedTypes);
        }
    }

    /**
     * Converts a generic KeyInterface to Halite-specific key type.
     */
    public function convertToHaliteKey(KeyInterface $key): HaliteKey|HaliteKeyPair
    {
        return $this->keyFactoryAdapter->getAdapterRequiredKey($key, $this->requiredKeyType);
    }

    /**
     * Expands key pairs into individual public/secret keys.
     */
    private function expandKeyPairs(array $keys): array
    {
        $expandedKeys = $keys;

        foreach ($keys as $key) {
            if (!$this->keyFactoryAdapter->isKeyPair($key->getType())) {
                continue;
            }

            $splitKeys = $this->keyFactoryAdapter->splitKeyPair($key, $this->requiredKeyType);
            $expandedKeys = array_merge($expandedKeys, $splitKeys);
        }

        return $expandedKeys;
    }

    /**
     * Finds a matching key or throws an error.
     */
    private function findKeyOrThrow(array $keys, array $allowedTypes): HaliteKey|HaliteKeyPair
    {
        foreach ($keys as $key) {
            if (in_array($key->getType(), $allowedTypes, true)) {
                return $this->convertToHaliteKey($key);
            }
        }

        throw new UnableToEncryptMessageException(
            "No key found matching types: " . implode(', ', $allowedTypes)
        );
    }
}
