<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\InvalidConnectionException;

/**
 * Interface for managing filesystem connections.
 * 
 * Implements a connection pool pattern for filesystem adapters, allowing
 * multiple adapters per connection type with priority-based selection.
 * 
 * Design pattern: Connection Pool + Strategy
 * - Manages multiple filesystem adapters
 * - Priority-based adapter selection
 * - Environment-aware path resolution
 * 
 * Default connections:
 * - keyring: Stores encrypted keyring files
 * - environment: Environment-specific files (.env, etc.)
 * - checksum: Checksum/integrity files
 * - master_keys: Master key storage
 * - vault: Secret vault storage
 * 
 * @see FilesystemAdapterInterface for adapter implementation
 */
interface FilesystemManagerInterface
{
    // Default connection types
    public const KEYRING = 'keyring';
    public const ENVIRONMENT = 'environment';
    public const CHECKSUM = 'checksum';
    public const MASTER_KEYS = 'master_keys';
    public const VAULT = 'vault';

    /**
     * Gets list of default connection names.
     * 
     * @return array<string> Default connection names
     */
    public function getDefaultConnections(): array;

    /**
     * Gets all registered connection names.
     * 
     * @return array<string> All connection names
     */
    public function getAllConnections(): array;

    /**
     * Sets the current environment for path resolution.
     * 
     * When set, paths will be prefixed with environment directory.
     * Example: If environment is 'production', path 'file.txt' becomes 'production/file.txt'
     * 
     * @param string|null $environment Environment name (null to disable)
     * @return void
     */
    public function setEnvironment(?string $environment): void;

    /**
     * Gets the current environment.
     * 
     * @return string|null Environment name or null
     */
    public function getEnvironment(): ?string;

    /**
     * Resolves a path with environment prefix if set.
     * 
     * @param string $path Relative path
     * @return string Resolved path with environment prefix
     */
    public function getPath(string $path): string;

    /**
     * Checks if a connection exists.
     * 
     * @param string $connection Connection name
     * @return bool True if connection exists
     */
    public function hasConnection(string $connection): bool;

    /**
     * Creates a new connection.
     * 
     * @param string $connection Connection name
     * @return void
     * @throws InvalidConnectionException If connection already exists
     */
    public function createConnection(string $connection): void;

    /**
     * Removes a connection.
     * 
     * Cannot remove default connections.
     * 
     * @param string $connection Connection name
     * @return void
     * @throws InvalidConnectionException If trying to remove default connection
     */
    public function removeConnection(string $connection): void;

    /**
     * Registers a filesystem adapter for a connection.
     * 
     * Higher priority adapters are tried first when resolving filesystems.
     * Multiple adapters can be registered for the same connection as fallbacks.
     * 
     * @param FilesystemAdapterInterface $adapter Filesystem adapter
     * @param string $connection Connection name
     * @param int $priority Priority (higher = higher priority, default 0)
     * @return void
     * @throws InvalidConnectionException If connection doesn't exist
     */
    public function registerAdapter(
        FilesystemAdapterInterface $adapter,
        string $connection,
        int $priority = 0
    ): void;

    /**
     * Gets a filesystem adapter for a connection.
     * 
     * Selection strategy:
     * - If path is null: Returns highest priority adapter
     * - If path provided: Returns first adapter that has the path
     * 
     * @param string $connection Connection name
     * @param string|null $path Optional path to check for existence
     * @return FilesystemAdapterInterface Filesystem adapter
     * @throws FilesystemNotFoundException If no adapter found
     * @throws InvalidConnectionException If connection doesn't exist
     */
    public function getFilesystem(string $connection, ?string $path = null): FilesystemAdapterInterface;

    /**
     * Gets all adapters for a connection in priority order.
     * 
     * @param string $connection Connection name
     * @return array<FilesystemAdapterInterface> Adapters in priority order
     * @throws InvalidConnectionException If connection doesn't exist
     */
    public function getAllAdapters(string $connection): array;

    /**
     * Counts adapters registered for a connection.
     * 
     * @param string $connection Connection name
     * @return int Number of adapters
     * @throws InvalidConnectionException If connection doesn't exist
     */
    public function countAdapters(string $connection): int;
}
