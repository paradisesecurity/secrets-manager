<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryAdapterInterface;

interface AdapterBasedKeyProviderInterface
{
    public function getSupportedAdapter(string $keyType): KeyFactoryAdapterInterface;

    public function supports(string $keyType): bool;
}
