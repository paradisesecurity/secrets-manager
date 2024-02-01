<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use League\Flysystem\Filesystem;
use League\Flysystem\Local\LocalFilesystemAdapter;
use League\Flysystem\UnixVisibility\PortableVisibilityConverter;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FlysystemFilesystemAdapter;

final class FilesystemAdapterSetup implements FilesystemAdapterSetupInterface
{
    public function setup(string $path): FilesystemAdapterInterface
    {
        $visibilityConverter = PortableVisibilityConverter::fromArray([
            'file' => [
                'public' => 0640,
                'private' => 0600,
            ],
            'dir' => [
                'public' => 0750,
                'private' => 0700,
            ],
        ]);

        $adapter = new LocalFilesystemAdapter($path, $visibilityConverter);
        $filesystem = new Filesystem($adapter);

        return new FlysystemFilesystemAdapter($filesystem, $path);
    }
}
