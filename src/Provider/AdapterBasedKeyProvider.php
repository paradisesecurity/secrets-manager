<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Exception\UnresolvedKeyProviderException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\PrioritizedServiceRegistryInterface;

final class AdapterBasedKeyProvider implements AdapterBasedKeyProviderInterface
{
    public function __construct(
        private PrioritizedServiceRegistryInterface $adapterRegistry
    ) {
    }

    public function getSupportedAdapter(
        string $keyType
    ): KeyFactoryAdapterInterface {
        foreach ($this->adapterRegistry->all() as $adapter) {
            if ($adapter->supports($keyType)) {
                return $adapter;
            }
        }

        throw new UnresolvedKeyProviderException();
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
}
