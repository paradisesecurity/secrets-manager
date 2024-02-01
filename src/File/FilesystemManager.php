<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

use Laminas\Stdlib\PriorityQueue;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;

use function array_key_exists;
use function in_array;
use function is_array;
use function is_int;
use function is_null;
use function is_string;

final class FilesystemManager implements FilesystemManagerInterface
{
    private array $connections = [];

    private ?string $environment = null;

    public function __construct(
        array $adapters = []
    ) {
        $this->createDefaultConnections();
        $this->processAdapters($adapters);
    }

    public function getDefaultConnections(): array
    {
        return [
            FilesystemManagerInterface::KEYRING,
            FilesystemManagerInterface::ENVIRONMENT,
            FilesystemManagerInterface::CHECKSUM,
            FilesystemManagerInterface::MASTER_KEYS,
            FilesystemManagerInterface::VAULT,
        ];
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
        $environment = '';
        if (!is_null($this->environment)) {
            $environment = $this->environment . '/';
        }
        return $environment . $path;
    }

    public function hasConnection(string $connection): bool
    {
        return array_key_exists($connection, $this->connections);
    }

    public function createConnection(string $connection): void
    {
        if (!$this->hasConnection($connection)) {
            $this->connections[$connection] = new PriorityQueue();
        }
    }

    public function removeConnection(string $connection): void
    {
        if ($this->hasConnection($connection) && !in_array($connection, $this->getDefaultConnections())) {
            unset($this->connections[$connection]);
        }
    }

    public function insert(FilesystemAdapterInterface $adapter, string $connection, int $priority = 0): void
    {
        if (!$this->hasConnection($connection)) {
            return;
        }

        $this->connections[$connection]->insert($adapter, $priority);
    }

    public function getFilesystem(string $connection, string $path = null): FilesystemAdapterInterface
    {
        $filesystems = new PriorityQueue();

        if ($this->hasConnection($connection)) {
            $filesystems = $this->connections[$connection];
        }

        if ($filesystems->isEmpty()) {
            throw new FilesystemNotFoundException();
        }

        if (is_null($path)) {
            return $filesystems->top();
        }

        foreach ($filesystems as $filesystem) {
            if (!$filesystem->has($path)) {
                continue;
            }
            return $filesystem;
        }

        throw new FilesystemNotFoundException();
    }

    private function createDefaultConnections(): void
    {
        $this->connections = [];
        foreach ($this->getDefaultConnections() as $connection) {
            $this->createConnection($connection);
        }
    }

    private function processAdapterConfig(array $config): void
    {
        $adapter = null;
        $connection = null;
        $priority = 0;
        foreach ($config as $item) {
            if (is_string($item)) {
                $connection = $item;
                continue;
            }
            if (is_int($item)) {
                $priority = $item;
                continue;
            }
            if ($item instanceof FilesystemAdapterInterface) {
                $adapter = $item;
                continue;
            }
        }
        if (!is_null($adapter) && !is_null($connection)) {
            $this->insert($adapter, $connection, $priority);
        }
    }

    private function processAdapters(array $adapters): void
    {
        foreach ($adapters as $config) {
            if (!is_array($config)) {
                continue;
            }
            $this->processAdapterConfig($config);
        }
    }
}
