<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Loader\DelegatingKeyLoader;
use ParadiseSecurity\Component\SecretsManager\Loader\DelegatingKeyLoaderInterface;
use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistry;

final class DelegatingKeyLoaderSetup implements DelegatingKeyLoaderSetupInterface
{
    public function setup(Collection $loaders): DelegatingKeyLoaderInterface
    {
        $registry = new ServiceRegistry(KeyStorageInterface::class);

        foreach ($loaders as $loader) {
            $registry->register($loader->getName(), $loader);
        }

        return new DelegatingKeyLoader($registry);
    }
}
