<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use League\Flysystem\Filesystem;
use League\Flysystem\Local\LocalFilesystemAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FlysystemFilesystemAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManager;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Loader\DelegatingKeyLoader;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParadiseSecurity\Component\SecretsManager\Storage\Env\EnvFileManager;
use ParadiseSecurity\Component\SecretsManager\Storage\EnvironmentBasedKeyStorage;
use ParadiseSecurity\Component\SecretsManager\Storage\FileBasedKeyStorage;
use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;
use ParadiseSecurity\Component\SecretsManager\Storage\Serialization\KeySerializer;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistry;

/**
 * Builder for creating configured FilesystemManager instances.
 * 
 * Provides fluent interface for setting up filesystem structure
 * with sensible defaults.
 */
final class StorageBuilder
{
    private string $masterKeyStorage = 'env';
    private ?string $envFile = '.env';
    private array $paths = [];
    private array $customAdapters = [];

    // Reusable services
    private ?KeySerializer $keySerializer = null;
    private ?EnvFileManager $envFileManager = null;

    public function useMasterKeyStorage(string $type): self
    {
        $this->masterKeyStorage = $type;
        return $this;
    }

    public function withEnvFile(string $file): self
    {
        $this->envFile = $file;
        return $this;
    }

    /**
     * Sets base paths for storage.
     * 
     * @param array{root: string, package: string} $paths Path configuration
     */
    public function withPaths(array $paths): self
    {
        $this->paths = $paths;
        return $this;
    }

    /**
     * Adds a custom adapter for a connection.
     * 
     * @param FilesystemAdapterInterface $adapter Filesystem adapter
     * @param string $connection Connection name
     * @param int $priority Priority (default 0)
     */
    public function withCustomAdapter(
        FilesystemAdapterInterface $adapter,
        string $connection,
        int $priority = 0
    ): self {
        $this->customAdapters[] = [$adapter, $connection, $priority];
        return $this;
    }

    /**
     * Builds the FilesystemManager.
     * 
     * Creates default adapters for standard connections if paths are provided.
     */
    public function build(): FilesystemManagerInterface
    {
        $adapters = [];

        // Create default adapters if paths provided
        if (!empty($this->paths)) {
            $adapters = $this->createDefaultAdapters();
        }

        // Add custom adapters
        $adapters = array_merge($adapters, $this->customAdapters);

        return new FilesystemManager($adapters);
    }

    /**
     * Creates default filesystem adapters from configured paths.
     * 
     * @return array<array{FilesystemAdapterInterface, string, int}>
     */
    private function createDefaultAdapters(): array
    {
        $root = $this->paths['root'] ?? throw new \InvalidArgumentException(
            'Root path is required'
        );
        $package = $this->paths['package'] ?? throw new \InvalidArgumentException(
            'Package path is required'
        );

        return [
            $this->createAdapter($package . '/keyring', FilesystemManagerInterface::KEYRING),
            $this->createAdapter($package . '/keyring', FilesystemManagerInterface::CHECKSUM),
            $this->createAdapter($root, FilesystemManagerInterface::ENVIRONMENT),
            $this->createAdapter($package . '/master-keys', FilesystemManagerInterface::MASTER_KEYS),
            $this->createAdapter($package . '/secrets', FilesystemManagerInterface::VAULT),
        ];
    }

    /**
     * Creates a filesystem adapter tuple.
     * 
     * @return array{FilesystemAdapterInterface, string, int}
     */
    private function createAdapter(string $path, string $connection, int $priority = 0): array
    {
        $localAdapter = new LocalFilesystemAdapter($path);
        $flysystem = new Filesystem($localAdapter);
        $wrapper = new FlysystemFilesystemAdapter($flysystem, $path);

        return [$wrapper, $connection, $priority];
    }

    public function buildMasterKeyProvider(FilesystemManagerInterface $filesystemManager): MasterKeyProviderInterface
    {
        // Initialize shared services
        $keySerializer = $this->getKeySerializer();
        $envFileManager = $this->getEnvFileManager();

        // Create storage implementations
        $envStorage = new EnvironmentBasedKeyStorage(
            $filesystemManager,
            $envFileManager,
            $keySerializer,
            $this->envFile
        );

        $fileStorage = new FileBasedKeyStorage(
            $filesystemManager,
            $keySerializer
        );

        // Register in service registry
        $storageRegistry = new ServiceRegistry(KeyStorageInterface::class);
        $storageRegistry->register('env', $envStorage);
        $storageRegistry->register('file', $fileStorage);

        // Create loader and provider
        $loader = new DelegatingKeyLoader($storageRegistry);

        return MasterKeyProvider::createDefault($loader, $this->masterKeyStorage);
    }

    private function getKeySerializer(): KeySerializer
    {
        if ($this->keySerializer === null) {
            $this->keySerializer = new KeySerializer();
        }
        
        return $this->keySerializer;
    }

    private function getEnvFileManager(): EnvFileManager
    {
        if ($this->envFileManager === null) {
            $this->envFileManager = new EnvFileManager();
        }
        
        return $this->envFileManager;
    }
}
