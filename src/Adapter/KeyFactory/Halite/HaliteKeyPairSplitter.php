<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\Halite;

use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\Halite\KeyPair as HaliteKeyPair;

use function str_replace;

/**
 * Splits Halite key pairs into individual keys.
 */
final class HaliteKeyPairSplitter
{
    public function __construct(
        private HaliteKeyConverter $keyConverter,
        private string $adapterName,
    ) {
    }

    /**
     * Splits a key pair into public and secret keys.
     */
    public function split(KeyInterface $keyPair, HaliteKeyPair $haliteKeyPair): array
    {
        $keys = [];
        $type = $keyPair->getType();
        $version = $keyPair->getVersion();

        $childTypes = $this->getChildKeyTypes($type);

        foreach ($childTypes as $childType) {
            if ($this->isPublicKeyType($childType)) {
                $publicKey = $haliteKeyPair->getPublicKey();
                $keys[] = $this->createKeyFromHaliteKey($publicKey, $childType, $version);
            }

            if ($this->isSecretKeyType($childType)) {
                $secretKey = $haliteKeyPair->getSecretKey();
                $keys[] = $this->createKeyFromHaliteKey($secretKey, $childType, $version);
            }
        }

        return $keys;
    }

    /**
     * Gets child key types for a key pair type.
     */
    private function getChildKeyTypes(string $keyPairType): array
    {
        $publicType = str_replace('key_pair', 'public_key', $keyPairType);
        $secretType = str_replace('key_pair', 'secret_key', $keyPairType);

        return [$publicType, $secretType];
    }

    /**
     * Checks if type represents a public key.
     */
    private function isPublicKeyType(string $type): bool
    {
        return str_contains($type, 'public_key');
    }

    /**
     * Checks if type represents a secret key.
     */
    private function isSecretKeyType(string $type): bool
    {
        return str_contains($type, 'secret_key');
    }

    /**
     * Creates a KeyInterface from Halite key.
     */
    private function createKeyFromHaliteKey(mixed $haliteKey, string $type, string $version): KeyInterface
    {
        $hex = $this->keyConverter->fromHaliteKey($haliteKey);
        return new Key($hex, $type, $this->adapterName, $version);
    }
}
