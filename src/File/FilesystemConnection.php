<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use Laminas\Stdlib\PriorityQueue;

/**
 * Represents a filesystem connection with priority-based adapter pool.
 * 
 * Manages multiple filesystem adapters with priority ordering.
 * Higher priority adapters are tried first.
 */
final class FilesystemConnection
{
    private PriorityQueue $adapters;

    public function __construct(
        private string $name
    ) {
        $this->adapters = new PriorityQueue();
    }

    /**
     * Gets the connection name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Adds an adapter with priority.
     * 
     * @param FilesystemAdapterInterface $adapter Filesystem adapter
     * @param int $priority Priority (higher = higher priority)
     */
    public function addAdapter(FilesystemAdapterInterface $adapter, int $priority = 0): void
    {
        $this->adapters->insert($adapter, $priority);
    }

    /**
     * Gets the highest priority adapter.
     * 
     * @return FilesystemAdapterInterface
     * @throws FilesystemNotFoundException If no adapters registered
     */
    public function getAdapter(): FilesystemAdapterInterface
    {
        if ($this->adapters->isEmpty()) {
            throw FilesystemNotFoundException::noAdapters($this->name);
        }

        return $this->adapters->top();
    }

    /**
     * Gets adapter that has the specified path.
     * 
     * Tries adapters in priority order until one with the path is found.
     * 
     * @param string $path Path to find
     * @return FilesystemAdapterInterface
     * @throws FilesystemNotFoundException If no adapter has the path
     */
    public function getAdapterWithPath(string $path): FilesystemAdapterInterface
    {
        if ($this->adapters->isEmpty()) {
            throw FilesystemNotFoundException::noAdapters($this->name);
        }

        foreach ($this->adapters as $adapter) {
            if ($adapter->has($path)) {
                return $adapter;
            }
        }

        throw FilesystemNotFoundException::pathNotFound($path, $this->name);
    }

    /**
     * Gets all adapters in priority order.
     * 
     * @return array<FilesystemAdapterInterface>
     */
    public function getAllAdapters(): array
    {
        $adapters = [];
        foreach ($this->adapters as $adapter) {
            $adapters[] = $adapter;
        }
        return $adapters;
    }

    /**
     * Checks if any adapters are registered.
     */
    public function hasAdapters(): bool
    {
        return !$this->adapters->isEmpty();
    }

    /**
     * Gets count of registered adapters.
     */
    public function countAdapters(): int
    {
        return $this->adapters->count();
    }
}
