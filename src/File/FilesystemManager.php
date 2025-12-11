<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\InvalidConnectionException;

use function array_key_exists;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function rtrim;

/**
 * Manages filesystem connections with priority-based adapter pooling.
 * 
 * Features:
 * - Multiple adapters per connection with priority ordering
 * - Environment-aware path resolution
 * - Default connections for common use cases
 * - Fallback adapter selection
 * 
 * Usage:
 * ```
 * $manager = new FilesystemManager([
 *     [$keyringAdapter, FilesystemManagerInterface::KEYRING, 100],
 *     [$vaultAdapter, FilesystemManagerInterface::VAULT, 50],
 * ]);
 * 
 * // Get filesystem for keyring
 * $fs = $manager->getFilesystem(FilesystemManagerInterface::KEYRING);
 * 
 * // Get filesystem that has specific path
 * $fs = $manager->getFilesystem(FilesystemManagerInterface::VAULT, 'secrets.vault');
 * ```
 */
final class FilesystemManager implements FilesystemManagerInterface
{
    /** @var array<string, FilesystemConnection> */
    private array $connections = [];

    private ?string $environment = null;

    /**
     * @param array<array{FilesystemAdapterInterface, string, int}> $adapters
     * Array of [adapter, connection, priority] tuples
     */
    public function __construct(array $adapters = [])
    {
        $this->initializeDefaultConnections();
        $this->registerAdapters($adapters);
    }

    public function getDefaultConnections(): array
    {
        return [
            self::KEYRING,
            self::ENVIRONMENT,
            self::CHECKSUM,
            self::MASTER_KEYS,
            self::VAULT,
        ];
    }

    public function getAllConnections(): array
    {
        return array_keys($this->connections);
    }

    public function setEnvironment(?string $environment): void
    {
        $this->environment = $environment;
    }

    public function getEnvironment(): ?string
    {
        return $this->environment;
    }

    public function getPath(string $path): string
    {
        if ($this->environment === null) {
            return $path;
        }

        $prefix = rtrim($this->environment, '/');
        return $prefix . '/' . ltrim($path, '/');
    }

    public function hasConnection(string $connection): bool
    {
        return array_key_exists($connection, $this->connections);
    }

    public function createConnection(string $connection): void
    {
        if ($this->hasConnection($connection)) {
            throw InvalidConnectionException::connectionAlreadyExists($connection);
        }

        $this->connections[$connection] = new FilesystemConnection($connection);
    }

    public function removeConnection(string $connection): void
    {
        if (!$this->hasConnection($connection)) {
            throw InvalidConnectionException::connectionNotFound($connection);
        }

        if ($this->isDefaultConnection($connection)) {
            throw InvalidConnectionException::cannotRemoveDefaultConnection($connection);
        }

        unset($this->connections[$connection]);
    }

    public function registerAdapter(
        FilesystemAdapterInterface $adapter,
        string $connection,
        int $priority = 0
    ): void {
        if (!$this->hasConnection($connection)) {
            throw InvalidConnectionException::connectionNotFound($connection);
        }

        $this->connections[$connection]->addAdapter($adapter, $priority);
    }

    public function getFilesystem(string $connection, ?string $path = null): FilesystemAdapterInterface
    {
        if (!$this->hasConnection($connection)) {
            throw InvalidConnectionException::connectionNotFound($connection);
        }

        $connectionObj = $this->connections[$connection];

        if (!$connectionObj->hasAdapters()) {
            throw InvalidConnectionException::noAdaptersRegistered($connection);
        }

        // If no path specified, return highest priority adapter
        if ($path === null) {
            return $connectionObj->getAdapter();
        }

        // Find adapter that has the specified path
        return $connectionObj->getAdapterWithPath($path);
    }

    public function getAllAdapters(string $connection): array
    {
        if (!$this->hasConnection($connection)) {
            throw InvalidConnectionException::connectionNotFound($connection);
        }

        return $this->connections[$connection]->getAllAdapters();
    }

    public function countAdapters(string $connection): int
    {
        if (!$this->hasConnection($connection)) {
            throw InvalidConnectionException::connectionNotFound($connection);
        }

        return $this->connections[$connection]->countAdapters();
    }

    /**
     * Checks if connection is a default connection.
     */
    private function isDefaultConnection(string $connection): bool
    {
        return in_array($connection, $this->getDefaultConnections(), true);
    }

    /**
     * Initializes default connections.
     */
    private function initializeDefaultConnections(): void
    {
        foreach ($this->getDefaultConnections() as $connection) {
            $this->connections[$connection] = new FilesystemConnection($connection);
        }
    }

    /**
     * Registers adapters from configuration array.
     * 
     * @param array<array{FilesystemAdapterInterface, string, int}> $adapters
     */
    private function registerAdapters(array $adapters): void
    {
        foreach ($adapters as $config) {
            if (!is_array($config)) {
                continue;
            }

            $this->registerAdapterFromConfig($config);
        }
    }

    /**
     * Registers a single adapter from configuration.
     * 
     * Expected format: [adapter, connection, priority]
     * Priority is optional (defaults to 0)
     * 
     * @param array $config Configuration array
     */
    private function registerAdapterFromConfig(array $config): void
    {
        $adapter = null;
        $connection = null;
        $priority = 0;

        foreach ($config as $item) {
            if ($item instanceof FilesystemAdapterInterface) {
                $adapter = $item;
            } elseif (is_string($item)) {
                $connection = $item;
            } elseif (is_int($item)) {
                $priority = $item;
            }
        }

        if ($adapter !== null && $connection !== null) {
            $this->registerAdapter($adapter, $connection, $priority);
        }
    }
}
