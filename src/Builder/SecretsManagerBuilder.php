<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManager;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\BuilderConfigurationException;
use ParadiseSecurity\Component\SecretsManager\Secret\Encryption\SecretEncryption;
use ParadiseSecurity\Component\SecretsManager\Secret\Authentication\SecretAuthentication;
use ParadiseSecurity\Component\SecretsManager\Secret\Key\SecretKeyBuilder;
use ParadiseSecurity\Component\SecretsManager\Secret\Cache\SecretCacheKeyManager;
use ParadiseSecurity\Component\SecretsManager\Secret\Serialization\SecretSerializer;

/**
 * Fluent builder for creating SecretManager instances.
 * Simplifies complex object construction with sensible defaults.
 */
final class SecretsManagerBuilder
{
    private bool $autoInitialize = false;
    private ?KeyInterface $authKey = null;
    private ?string $keyringName = 'keyring';
    private ?string $vault = null;
    private array $options = [];
    private array $paths = [];
    
    // Sub-builders
    private ?EncryptionBuilder $encryptionBuilder = null;
    private ?StorageBuilder $storageBuilder = null;
    private ?VaultBuilder $vaultBuilder = null;

    private function __construct()
    {
        $this->encryptionBuilder = new EncryptionBuilder();
        $this->storageBuilder = new StorageBuilder();
        $this->vaultBuilder = new VaultBuilder();
    }

    public static function create(): self
    {
        return new self();
    }

    /**
     * Set the authentication key for the keyring.
     */
    public function withAuthKey(KeyInterface $authKey): self
    {
        $this->authKey = $authKey;
        return $this;
    }

    /**
     * Set the keyring name (default: 'keyring').
     */
    public function withKeyringName(string $name): self
    {
        $this->keyringName = $name;
        return $this;
    }

    /**
     * Set the default vault to use.
     */
    public function withDefaultVault(string $vault): self
    {
        $this->vault = $vault;
        return $this;
    }

    /**
     * Set default options for vault operations.
     */
    public function withOptions(array $options): self
    {
        $this->options = $options;
        return $this;
    }

    /**
     * Configure base paths for storage.
     */
    public function withPaths(string $root, ?string $package = null): self
    {
        $this->paths['root'] = $root;
        $this->paths['package'] = $package ?? $root . '/config/secrets-manager';
        return $this;
    }

    /**
     * Configure encryption settings via fluent sub-builder.
     */
    public function configureEncryption(callable $callback): self
    {
        $callback($this->encryptionBuilder);
        return $this;
    }

    /**
     * Configure storage settings via fluent sub-builder.
     */
    public function configureStorage(callable $callback): self
    {
        $callback($this->storageBuilder);
        return $this;
    }

    /**
     * Configure vault adapter via fluent sub-builder.
     */
    public function configureVault(callable $callback): self
    {
        $callback($this->vaultBuilder);
        return $this;
    }

    /**
     * Enable automatic initialization during build if not already set up.
     * Use with caution - prefer explicit setup in production.
     */
    public function withAutoInitialize(bool $enable = true): self
    {
        $this->autoInitialize = $enable;
        return $this;
    }

    /**
     * Build and return the SecretManager instance.
     */
    public function build(): SecretManagerInterface
    {
        $this->validate();

        // Build filesystem manager first
        $filesystemManager = $this->storageBuilder
            ->withPaths($this->paths)
            ->build();

        // Check if initialization is needed
        /* Disabled for now
        $setupCommand = new SetupCommand($filesystemManager);
        if (!$setupCommand->isInitialized()) {
            $this->runSetupCommand($setupCommand);
        }
        */

        // Build encryption components
        $encryptionAdapter = $this->encryptionBuilder->build();
        $keyFactory = $this->encryptionBuilder->buildKeyFactory();

        // Build storage components
        $masterKeyProvider = $this->storageBuilder
            ->buildMasterKeyProvider($filesystemManager);

        // Build vault adapter
        $vaultAdapter = $this->vaultBuilder
            ->withFilesystemManager($filesystemManager)
            ->build();

        // Build KeyManager
        $keyManager = KeyManagerBuilder::create()
            ->withFilesystemManager($filesystemManager)
            ->withMasterKeyProvider($masterKeyProvider)
            ->withEncryptionAdapter($encryptionAdapter)
            ->withKeyFactory($keyFactory)
            ->withKeyringName($this->keyringName)
            ->build();

        // Build SecretManager services
        $secretEncryption = new SecretEncryption($encryptionAdapter);
        $secretAuthentication = new SecretAuthentication($encryptionAdapter);
        $keyBuilder = new SecretKeyBuilder($keyFactory);
        $cacheKeyManager = new SecretCacheKeyManager();
        $serializer = new SecretSerializer();

        return new SecretManager(
            $vaultAdapter,
            $keyManager,
            $secretEncryption,
            $secretAuthentication,
            $keyBuilder,
            $cacheKeyManager,
            $serializer,
            $this->authKey,
            $this->vault ?? '',
            $this->options
        );
    }

    private function runSetupCommand($setupCommand): void
    {
        if ($this->autoInitialize) {
            // Auto-initialize if enabled
            $result = $setupCommand->initialize();
            if (!$result->isSuccess()) {
                throw new BuilderConfigurationException(
                    'Auto-initialization failed: ' . $result->getFormattedOutput()
                );
            }
        }

        // Throw helpful error message
        throw new BuilderConfigurationException(
            "Secrets manager is not initialized. Run setup first:\n" .
            "\$setupCommand = new SetupCommand(\$filesystemManager);\n" .
            "\$setupCommand->initialize();\n" .
            "Or enable auto-initialization (not recommended for production):\n" .
            "->withAutoInitialize(true)"
        );
    }

    private function validate(): void
    {
        if ($this->authKey === null) {
            throw new BuilderConfigurationException('Authentication key is required. Use withAuthKey().');
        }

        if (empty($this->paths)) {
            throw new BuilderConfigurationException('Paths must be configured. Use withPaths().');
        }
    }
}
