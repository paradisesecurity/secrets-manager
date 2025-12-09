<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;

interface KeyManagerSetupInterface extends SetupInterface
{
    public function setup(
        FilesystemManagerInterface $manager,
        EncryptionAdapterInterface $encryption,
        Collection $adapters,
        Collection $loaders,
        string $storage,
        string $name
    ): KeyManagerInterface;
}
