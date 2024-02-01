<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use ParadiseSecurity\Component\SecretsManager\File\FilesystemAdapterInterface;

interface FilesystemAdapterSetupInterface extends SetupInterface
{
    public function setup(string $path): FilesystemAdapterInterface;
}
