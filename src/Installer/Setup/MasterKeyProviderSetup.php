<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;

final class MasterKeyProviderSetup implements MasterKeyProviderSetupInterface
{
    public function setup(Collection $loaders, string $storage): MasterKeyProviderInterface
    {
        $setup = new DelegatingKeyLoaderSetup();
        $loader = $setup->setup($loaders);

        return new MasterKeyProvider($loader, $storage);
    }
}
