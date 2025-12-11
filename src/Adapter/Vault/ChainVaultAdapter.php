<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Chain of Responsibility vault adapter.
 * 
 * Manages multiple vault adapters and tries them in sequence:
 * - getSecret: Returns from first adapter that has the secret
 * - putSecret: Stores in all adapters
 * - deleteSecret: Deletes from all adapters
 * 
 * Typical use case: Primary storage (filesystem) + fallback storage (database)
 * or layered caching (memory cache -> file cache -> database).
 * 
 * Example:
 * ```
 * $chain = new ChainVaultAdapter([
 *     new PSR6CacheVaultAdapter($fileAdapter, $memoryCache),  // Fast cache
 *     new FilesystemVaultAdapter($filesystemManager),          // Persistent storage
 * ]);
 * ```
 * 
 * @see https://refactoring.guru/design-patterns/chain-of-responsibility
 */
final class ChainVaultAdapter extends AbstractVaultAdapter
{
    /** @var array<int, VaultAdapterInterface> */
    private array $adapters = [];

    /**
     * @param array<VaultAdapterInterface> $adapters Vault adapters in priority order
     */
    public function __construct(array $adapters)
    {
        foreach ($adapters as $adapter) {
            if ($adapter instanceof VaultAdapterInterface) {
                $this->adapters[] = $adapter;
            }
        }

        if (empty($this->adapters)) {
            throw new \InvalidArgumentException(
                'ChainVaultAdapter requires at least one VaultAdapterInterface'
            );
        }
    }

    /**
     * Tries each adapter in order until secret is found.
     * Chain of Responsibility pattern: first successful handler wins.
     */
    public function getSecret(string $key, array $options = []): SecretInterface
    {
        $lastException = null;

        foreach ($this->adapters as $index => $adapter) {
            try {
                $adapterOptions = $this->getAdapterOptions($options, $index);
                return $adapter->getSecret($key, $adapterOptions);
            } catch (SecretNotFoundException $exception) {
                $lastException = $exception;
                continue;
            }
        }

        throw $lastException ?? SecretNotFoundException::withKey($key);
    }

    /**
     * Stores secret in ALL adapters (write-through strategy).
     * Ensures consistency across all storage layers.
     */
    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        $exceptions = [];

        foreach ($this->adapters as $index => $adapter) {
            try {
                $adapterOptions = $this->getAdapterOptions($options, $index);
                $adapter->putSecret($secret, $adapterOptions);
            } catch (\Exception $exception) {
                $exceptions[] = $exception;
            }
        }

        if (!empty($exceptions)) {
            throw new \RuntimeException(
                sprintf('Failed to put secret in %d adapter(s)', count($exceptions)),
                0,
                $exceptions[0]
            );
        }

        return $secret;
    }

    /**
     * Deletes secret from ALL adapters.
     */
    public function deleteSecret(SecretInterface $secret, array $options = []): void
    {
        foreach ($this->adapters as $index => $adapter) {
            try {
                $adapterOptions = $this->getAdapterOptions($options, $index);
                $adapter->deleteSecret($secret, $adapterOptions);
            } catch (SecretNotFoundException) {
                // Continue even if not found in this adapter
                continue;
            }
        }
    }

    /**
     * Deletes secret by key from ALL adapters.
     */
    public function deleteSecretByKey(string $key, array $options): void
    {
        $foundInAny = false;

        foreach ($this->adapters as $index => $adapter) {
            try {
                $adapterOptions = $this->getAdapterOptions($options, $index);
                $adapter->deleteSecretByKey($key, $adapterOptions);
                $foundInAny = true;
            } catch (SecretNotFoundException) {
                continue;
            }
        }

        if (!$foundInAny) {
            throw SecretNotFoundException::withKey($key);
        }
    }

    /**
     * Deletes vault from ALL adapters.
     */
    public function deleteVault(array $options = []): void
    {
        foreach ($this->adapters as $index => $adapter) {
            $adapterOptions = $this->getAdapterOptions($options, $index);
            $adapter->deleteVault($adapterOptions);
        }
    }

    /**
     * Configures shared options for all adapters.
     */
    public function configureSharedOptions(OptionsResolver $resolver): void
    {
        parent::configureSharedOptions($resolver);

        foreach ($this->adapters as $adapter) {
            $adapter->configureSharedOptions($resolver);
        }
    }

    public function configureGetSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureGetSecretOptions($resolver);

        foreach ($this->adapters as $adapter) {
            $adapter->configureGetSecretOptions($resolver);
        }
    }

    public function configurePutSecretOptions(OptionsResolver $resolver): void
    {
        parent::configurePutSecretOptions($resolver);

        foreach ($this->adapters as $adapter) {
            $adapter->configurePutSecretOptions($resolver);
        }
    }

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureDeleteSecretOptions($resolver);

        foreach ($this->adapters as $adapter) {
            $adapter->configureDeleteSecretOptions($resolver);
        }
    }

    /**
     * Gets options for a specific adapter.
     * 
     * Allows per-adapter options using array keys:
     * ```
     * $options = [
     *     'vault' => 'my-vault',
     *     0 => ['ttl' => 60],      // Options for first adapter
     *     1 => ['path' => '/tmp'], // Options for second adapter
     * ];
     * ```
     * 
     * @param array $options Global options
     * @param int $index Adapter index
     * @return array Merged options for adapter
     */
    private function getAdapterOptions(array $options, int $index): array
    {
        return $options[$index] ?? $options;
    }

    /**
     * Gets all registered adapters.
     * 
     * Useful for testing and introspection.
     * 
     * @return array<VaultAdapterInterface>
     */
    public function getAdapters(): array
    {
        return $this->adapters;
    }

    /**
     * Gets the number of adapters in the chain.
     * 
     * @return int
     */
    public function count(): int
    {
        return count($this->adapters);
    }
}
