<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProviderInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\PrioritizedServiceRegistry;

final class KeyProviderSetup implements KeyProviderSetupInterface
{
    public function setup(Collection $adapters): AdapterBasedKeyProviderInterface
    {
        $registry = new PrioritizedServiceRegistry(KeyFactoryAdapterInterface::class);

        foreach ($adapters as $adapter) {
            $registry->register($adapter);
        }

        return new AdapterBasedKeyProvider($registry);
    }
}
