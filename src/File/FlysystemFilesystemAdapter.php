<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

use League\Flysystem\FilesystemException;
use League\Flysystem\FilesystemOperator;
use League\Flysystem\PathPrefixer;
use League\Flysystem\UnableToCheckExistence;
use League\Flysystem\UnableToCreateDirectory;
use League\Flysystem\UnableToDeleteFile;
use League\Flysystem\UnableToReadFile;
use League\Flysystem\UnableToRetrieveMetadata;
use League\Flysystem\UnableToSetVisibility;
use League\Flysystem\UnableToWriteFile;
use League\Flysystem\Visibility;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;

use function strrpos;

use const DIRECTORY_SEPARATOR;

final class FlysystemFilesystemAdapter implements FilesystemAdapterInterface
{
    private PathPrefixer $prefixer;

    public function __construct(
        private FilesystemOperator $filesystem,
        string $location,
    ) {
        $this->root = $location;
        $this->prefixer = new PathPrefixer($location, DIRECTORY_SEPARATOR);
    }

    public function has(string $path): bool
    {
        try {
            return $this->filesystem->has($path);
        } catch (FilesystemException | UnableToCheckExistence $exception) {
            return false;
        }
    }

    public function read(string $path): string
    {
        try {
            return $this->filesystem->read($path);
        } catch (FilesystemException | UnableToReadFile $exception) {
            throw new FilesystemErrorException('Could not read file contents.', $exception);
        }
    }

    public function open(string $path): mixed
    {
        try {
            return $this->filesystem->readStream($path);
        } catch (FilesystemException | UnableToReadFile $exception) {
            throw new FilesystemErrorException('Could not open file for access.', $exception);
        }
    }

    public function close(string $path): void
    {
        return;
    }

    public function save(string $path, string $contents, array $config = []): void
    {
        try {
            $this->filesystem->write($path, $contents, $config);
        } catch (FilesystemException | UnableToWriteFile $exception) {
            throw new FilesystemErrorException('Could not save file.', $exception);
        }
    }

    public function write(string $path, string $stream, array $config = []): void
    {
        try {
            $this->filesystem->writeStream($path, $stream, $config);
        } catch (FilesystemException | UnableToWriteFile $exception) {
            throw new FilesystemErrorException('Could not write data into file.', $exception);
        }
    }

    public function delete(string $path): void
    {
        try {
            $this->filesystem->delete($path);
        } catch (FilesystemException | UnableToDeleteFile $exception) {
            throw new FilesystemErrorException('Could not delete file.', $exception);
        }
    }

    public function mkdir(string $path, array $config = []): void
    {
        try {
            $this->filesystem->createDirectory($path, $config);
        } catch (FilesystemException | UnableToCreateDirectory $exception) {
            throw new FilesystemErrorException('Could not create directory.', $exception);
        }
    }

    public function permission(string $path, string $permission): bool
    {
        if ($permission !== Visibility::PUBLIC && $permission !== Visibility::PRIVATE) {
            return false;
        }
        try {
            return ($this->filesystem->visibility($path) === $permission);
        } catch (FilesystemException | UnableToRetrieveMetadata $exception) {
            return false;
        }
    }

    public function chmod(string $path, string $visibility): void
    {
        if ($visibility !== Visibility::PUBLIC && $visibility !== Visibility::PRIVATE) {
            throw new FilesystemErrorException('Could not change permissions.');
        }
        try {
            $this->filesystem->setVisibility($path, $visibility);
        } catch (FilesystemException | UnableToSetVisibility $exception) {
            throw new FilesystemErrorException('Could not change permissions.', $exception);
        }
    }

    public function realpath(string $path = ''): string
    {
        if ($this->isFile($path)) {
            return $this->prefixer->prefixPath($path);
        }

        return $this->prefixer->prefixDirectoryPath($path);
    }

    private function isFile(string $path): bool
    {
        $position = strrpos($path, '.');
        return ($position !== false);
    }
}
