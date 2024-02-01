<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;

interface FilesystemManagerSetupInterface extends SetupInterface
{
    public function setup(array $options): FilesystemManagerInterface;
}
