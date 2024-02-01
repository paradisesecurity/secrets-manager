<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManager;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;

final class KeyManagerSetup implements KeyManagerSetupInterface
{
    public function setup(
        FilesystemManagerInterface $manager,
        EncryptionAdapterInterface $encryption,
        Collection $adapters,
        Collection $loaders,
        string $storage,
        string $name
    ): KeyManagerInterface {
        $factorySetup = new KeyFactorySetup();
        $factory = $factorySetup->setup($adapters);

        $providerSetup = new MasterKeyProviderSetup();
        $provider = $providerSetup->setup($loaders, $storage);

        return new KeyManager(
            $manager,
            $provider,
            $encryption,
            $factory,
            $name
        );
    }
}
