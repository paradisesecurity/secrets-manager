<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Loader;

use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;

interface DelegatingKeyLoaderInterface
{
    public function getLoader(string $loader): KeyStorageInterface;
}
