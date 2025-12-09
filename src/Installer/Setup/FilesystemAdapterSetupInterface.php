<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;

interface FilesystemAdapterSetupInterface extends SetupInterface
{
    public function setup(string $path): FilesystemAdapterInterface;
}
