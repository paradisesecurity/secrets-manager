<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem;

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

use function is_resource;
use function strrpos;

use const DIRECTORY_SEPARATOR;

/**
 * Filesystem adapter using League Flysystem.
 * 
 * Wraps Flysystem's FilesystemOperator to provide a consistent interface
 * for filesystem operations. Supports local, cloud (S3, Azure, etc.), and
 * other storage backends through Flysystem's adapter ecosystem.
 * 
 * @see https://flysystem.thephpleague.com/
 */
final class FlysystemFilesystemAdapter implements FilesystemAdapterInterface
{
    private PathPrefixer $prefixer;
    
    private string $root;

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
        } catch (FilesystemException | UnableToCheckExistence) {
            return false;
        }
    }

    public function fileExists(string $path): bool
    {
        try {
            return $this->filesystem->fileExists($path);
        } catch (FilesystemException | UnableToCheckExistence) {
            return false;
        }
    }

    public function directoryExists(string $path): bool
    {
        try {
            return $this->filesystem->directoryExists($path);
        } catch (FilesystemException | UnableToCheckExistence) {
            return false;
        }
    }

    public function read(string $path): string
    {
        try {
            return $this->filesystem->read($path);
        } catch (FilesystemException | UnableToReadFile $exception) {
            throw new FilesystemErrorException(
                "Could not read file contents: {$path}",
                $exception
            );
        }
    }

    public function open(string $path): mixed
    {
        try {
            return $this->filesystem->readStream($path);
        } catch (FilesystemException | UnableToReadFile $exception) {
            throw new FilesystemErrorException(
                "Could not open file for access: {$path}",
                $exception
            );
        }
    }

    public function close(mixed $stream): void
    {
        if (is_resource($stream)) {
            @fclose($stream);
        }
    }

    public function save(string $path, string $contents, array $config = []): void
    {
        try {
            $this->filesystem->write($path, $contents, $config);
        } catch (FilesystemException | UnableToWriteFile $exception) {
            throw new FilesystemErrorException(
                "Could not save file: {$path}",
                $exception
            );
        }
    }

    public function write(string $path, mixed $stream, array $config = []): void
    {
        try {
            $this->filesystem->writeStream($path, $stream, $config);
        } catch (FilesystemException | UnableToWriteFile $exception) {
            throw new FilesystemErrorException(
                "Could not write stream to file: {$path}",
                $exception
            );
        }
    }

    public function delete(string $path): void
    {
        try {
            $this->filesystem->delete($path);
        } catch (FilesystemException | UnableToDeleteFile $exception) {
            throw new FilesystemErrorException(
                "Could not delete file: {$path}",
                $exception
            );
        }
    }

    public function mkdir(string $path, array $config = []): void
    {
        try {
            $this->filesystem->createDirectory($path, $config);
        } catch (FilesystemException | UnableToCreateDirectory $exception) {
            throw new FilesystemErrorException(
                "Could not create directory: {$path}",
                $exception
            );
        }
    }

    public function permission(string $path, string $permission): bool
    {
        if (!$this->isValidVisibility($permission)) {
            return false;
        }

        try {
            return $this->filesystem->visibility($path) === $permission;
        } catch (FilesystemException | UnableToRetrieveMetadata) {
            return false;
        }
    }

    public function chmod(string $path, string $visibility): void
    {
        if (!$this->isValidVisibility($visibility)) {
            throw new FilesystemErrorException(
                "Invalid visibility value: {$visibility}. Must be 'public' or 'private'."
            );
        }

        try {
            $this->filesystem->setVisibility($path, $visibility);
        } catch (FilesystemException | UnableToSetVisibility $exception) {
            throw new FilesystemErrorException(
                "Could not change permissions for: {$path}",
                $exception
            );
        }
    }

    public function realpath(string $path = ''): string
    {
        if (empty($path)) {
            return $this->prefixer->prefixDirectoryPath('');
        }

        if ($this->isFilePath($path)) {
            return $this->prefixer->prefixPath($path);
        }

        return $this->prefixer->prefixDirectoryPath($path);
    }

    public function getRoot(): string
    {
        return $this->root;
    }

    /**
     * Validates if visibility value is valid.
     */
    private function isValidVisibility(string $visibility): bool
    {
        return $visibility === Visibility::PUBLIC || $visibility === Visibility::PRIVATE;
    }

    /**
     * Determines if a path represents a file (has extension).
     * 
     * This is a heuristic check. More accurate would be to query the filesystem,
     * but that requires an additional operation.
     */
    private function isFilePath(string $path): bool
    {
        $position = strrpos($path, '.');
        return $position !== false && $position > strrpos($path, '/');
    }
}

