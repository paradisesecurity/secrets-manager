<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem;

/**
 * Interface for filesystem adapters.
 * 
 * Provides a consistent API for different filesystem backends (local, cloud, etc.).
 * Implementations can use Flysystem, native PHP functions, or other filesystem libraries.
 * 
 * This adapter pattern allows the SecretsManager to work with various storage
 * backends without coupling to specific implementations.
 * 
 * @see FlysystemFilesystemAdapter for a Flysystem-based implementation
 */
interface FilesystemAdapterInterface
{
    /**
     * Checks if a file or directory exists.
     * 
     * @param string $path Path to check
     * @return bool True if exists, false otherwise
     */
    public function has(string $path): bool;

    /**
     * Checks if the path represents a file (not a directory).
     * 
     * @param string $path Path to check
     * @return bool True if file exists, false otherwise
     */
    public function fileExists(string $path): bool;

    /**
     * Checks if the path represents a directory.
     * 
     * @param string $path Path to check
     * @return bool True if directory exists, false otherwise
     */
    public function directoryExists(string $path): bool;

    /**
     * Reads entire file contents as a string.
     * 
     * @param string $path File path to read
     * @return string File contents
     * @throws FilesystemErrorException If file cannot be read
     */
    public function read(string $path): string;

    /**
     * Opens a file and returns a resource stream.
     * 
     * Used for streaming large files without loading entire content into memory.
     * 
     * @param string $path File path to open
     * @return resource File stream resource
     * @throws FilesystemErrorException If file cannot be opened
     */
    public function open(string $path): mixed;

    /**
     * Closes an open file stream.
     * 
     * @param mixed $stream File stream to close
     * @return void
     */
    public function close(mixed $stream): void;

    /**
     * Writes string content to a file (overwrites if exists).
     * 
     * @param string $path File path to write
     * @param string $contents Content to write
     * @param array $config Additional configuration (visibility, metadata, etc.)
     * @return void
     * @throws FilesystemErrorException If write fails
     */
    public function save(string $path, string $contents, array $config = []): void;

    /**
     * Writes a stream to a file (overwrites if exists).
     * 
     * @param string $path File path to write
     * @param resource $stream Stream resource to write
     * @param array $config Additional configuration
     * @return void
     * @throws FilesystemErrorException If write fails
     */
    public function write(string $path, mixed $stream, array $config = []): void;

    /**
     * Deletes a file.
     * 
     * @param string $path File path to delete
     * @return void
     * @throws FilesystemErrorException If deletion fails
     */
    public function delete(string $path): void;

    /**
     * Creates a directory (creates parent directories if needed).
     * 
     * @param string $path Directory path to create
     * @param array $config Additional configuration (visibility, permissions)
     * @return void
     * @throws FilesystemErrorException If directory creation fails
     */
    public function mkdir(string $path, array $config = []): void;

    /**
     * Checks if a file/directory has specific permissions.
     * 
     * @param string $path Path to check
     * @param string $permission Permission level to check (e.g., 'public', 'private')
     * @return bool True if has permission, false otherwise
     */
    public function permission(string $path, string $permission): bool;

    /**
     * Changes file/directory permissions (chmod equivalent).
     * 
     * @param string $path Path to modify
     * @param string $visibility Visibility/permission level (e.g., 'public', 'private')
     * @return void
     * @throws FilesystemErrorException If permission change fails
     */
    public function chmod(string $path, string $visibility): void;

    /**
     * Gets the absolute real path for a relative path.
     * 
     * Resolves the path relative to the adapter's root location.
     * 
     * @param string $path Relative path (empty for root)
     * @return string Absolute path
     */
    public function realpath(string $path = ''): string;

    /**
     * Gets the adapter's root location.
     * 
     * @return string Root directory path
     */
    public function getRoot(): string;
}
