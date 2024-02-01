<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use ParadiseSecurity\Component\SecretsManager\File\FilesystemManager;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;

final class FilesystemManagerSetup implements FilesystemManagerSetupInterface
{
    public function setup(array $options): FilesystemManagerInterface
    {
        $adapter = new FilesystemAdapterSetup();

        $config = [];
        foreach ($options as $connection => $path) {
            $config[] = [$adapter->setup($path), $connection];
        }

        return new FilesystemManager($config);
    }
}
