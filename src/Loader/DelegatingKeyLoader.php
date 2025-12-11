<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Loader;

use ParadiseSecurity\Component\SecretsManager\Exception\KeyLoaderException;
use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistryInterface;

/**
 * Delegating key loader using service registry.
 * 
 * Delegates key loading to registered storage implementations.
 */
final class DelegatingKeyLoader implements DelegatingKeyLoaderInterface
{
    public function __construct(
        private ServiceRegistryInterface $registry
    ) {
    }

    public function getLoader(string $loaderName): KeyStorageInterface
    {
        if (!$this->hasLoader($loaderName)) {
            throw KeyLoaderException::loaderNotFound(
                $loaderName,
                $this->getLoaderNames()
            );
        }

        return $this->registry->get($loaderName);
    }

    public function hasLoader(string $loaderName): bool
    {
        return $this->registry->has($loaderName);
    }

    public function getLoaderNames(): array
    {
        return array_keys($this->registry->all());
    }
}
