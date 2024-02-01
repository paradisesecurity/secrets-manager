<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Loader;

use ParadiseSecurity\Component\SecretsManager\Exception\UndefinedKeyLoaderException;
use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistryInterface;

final class DelegatingKeyLoader implements DelegatingKeyLoaderInterface
{
    public function __construct(
        private ServiceRegistryInterface $registry
    ) {
    }

    public function getLoader(string $loader): KeyStorageInterface
    {
        if ($this->registry->has($loader)) {
            return $this->registry->get($loader);
        }

        throw new UndefinedKeyLoaderException('Cannot load encryption keys without a defined key loader.');
    }
}
