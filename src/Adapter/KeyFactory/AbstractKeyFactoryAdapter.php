<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory;

use ParadiseSecurity\Component\SecretsManager\Adapter\AbstractAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

use function in_array;
use function str_contains;

/**
 * Abstract base for key factory adapters.
 * 
 * Provides common functionality for all key factory implementations,
 * including key type checking, parent/child relationship management,
 * and utility methods.
 */
abstract class AbstractKeyFactoryAdapter extends AbstractAdapter implements KeyFactoryAdapterInterface
{
    protected array $supported = [];

    public function getSupportedKeyTypes(): array
    {
        return $this->supported;
    }

    public function supports(string $keyType): bool
    {
        return in_array($keyType, $this->supported, true);
    }

    public function getParentKey(string $type): array
    {
        $encryptionKeyPair = $this->getChildKeys(KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR);
        if (in_array($type, $encryptionKeyPair, true)) {
            return [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR];
        }

        $signatureKeyPair = $this->getChildKeys(KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR);
        if (in_array($type, $signatureKeyPair, true)) {
            return [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR];
        }

        return [];
    }

    public function getChildKeys(string $type): array
    {
        return match ($type) {
            KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR => [
                KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
                KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
            ],
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR => [
                KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
                KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY,
            ],
            default => [],
        };
    }

    public function isKeyPair(string $type): bool
    {
        return str_contains($type, 'key_pair');
    }

    public function isPublicKey(string $type): bool
    {
        return str_contains($type, 'public_key');
    }

    public function isSecretKey(string $type): bool
    {
        return str_contains($type, 'secret_key');
    }

    /**
     * Gets hex representation from key.
     */
    protected function getHexKey(KeyInterface $key): HiddenString
    {
        return $key->getHex();
    }
}
