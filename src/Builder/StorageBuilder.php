<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use League\Flysystem\Filesystem;
use League\Flysystem\Local\LocalFilesystemAdapter;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManager;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FlysystemFilesystemAdapter;
use ParadiseSecurity\Component\SecretsManager\Storage\FileBasedKeyStorage;
use ParadiseSecurity\Component\SecretsManager\Storage\EnvironmentBasedKeyStorage;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistry;
use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;
use ParadiseSecurity\Component\SecretsManager\Loader\DelegatingKeyLoader;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Storage\Env\EnvFileManager;
use ParadiseSecurity\Component\SecretsManager\Storage\Serialization\KeySerializer;

/**
 * Sub-builder for filesystem and storage configuration.
 */
final class StorageBuilder
{
    private string $masterKeyStorage = 'env';
    private ?string $envFile = '.env';
    private array $paths = [];

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

    public function withPaths(array $paths): self
    {
        $this->paths = $paths;
        return $this;
    }

    public function build(): FilesystemManagerInterface
    {
        $root = $this->paths['root'];
        $package = $this->paths['package'];

        // Create filesystem adapters
        $keyringAdapter = new LocalFilesystemAdapter($package . '/keyring');
        $keyringStorage = new Filesystem($keyringAdapter);
        $keyringWrapper = new FlysystemFilesystemAdapter(
            $keyringStorage,
            $package . '/keyring'
        );

        $checksumAdapter = new LocalFilesystemAdapter($package . '/keyring');
        $checksumStorage = new Filesystem($checksumAdapter);
        $checksumWrapper = new FlysystemFilesystemAdapter(
            $checksumStorage,
            $package . '/keyring'
        );

        $envAdapter = new LocalFilesystemAdapter($root);
        $envStorage = new Filesystem($envAdapter);
        $envWrapper = new FlysystemFilesystemAdapter(
            $envStorage,
            $root
        );

        $masterKeysAdapter = new LocalFilesystemAdapter($package . '/master-keys');
        $masterKeysStorage = new Filesystem($masterKeysAdapter);
        $masterKeysWrapper = new FlysystemFilesystemAdapter(
            $masterKeysStorage,
            $package . '/master-keys'
        );

        $vaultAdapter = new LocalFilesystemAdapter($package . '/vault');
        $vaultStorage = new Filesystem($vaultAdapter);
        $vaultWrapper = new FlysystemFilesystemAdapter(
            $vaultStorage,
            $package . '/vault'
        );

        $filesystemConfig = [
            [$keyringWrapper, FilesystemManagerInterface::KEYRING],
            [$checksumWrapper, FilesystemManagerInterface::CHECKSUM],
            [$envWrapper, FilesystemManagerInterface::ENVIRONMENT],
            [$masterKeysWrapper, FilesystemManagerInterface::MASTER_KEYS],
            [$vaultWrapper, FilesystemManagerInterface::VAULT],
        ];

        return new FilesystemManager($filesystemConfig);
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

        return new MasterKeyProvider($loader, $this->masterKeyStorage);
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
