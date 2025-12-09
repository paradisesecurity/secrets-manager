<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactory;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistry;

final class KeyFactorySetup implements KeyFactorySetupInterface
{
    public function setup(Collection $adapters): KeyFactoryInterface
    {
        $registry = new ServiceRegistry(KeyFactoryAdapterInterface::class);

        foreach ($adapters as $adapter) {
            $registry->register($adapter->getName(), $adapter);
        }

        return new KeyFactory($registry);
    }
}
