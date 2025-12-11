<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use \ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\HaliteKeyFactoryAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\HaliteEncryptionAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactory;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProviderInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\PrioritizedServiceRegistry;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistry;

/**
 * Builder for encryption and key factory services.
 * 
 * Architecture:
 * 1. KeyFactory: Generates keys, indexed by adapter NAME
 * 2. AdapterBasedKeyProvider: Finds adapters by key TYPE support  
 * 3. EncryptionAdapter: Performs encryption/decryption operations
 * 
 * The builder supports:
 * - Default adapters (built-in: Halite)
 * - Custom adapters (user-provided)
 * - Lazy initialization (only builds when requested)
 * 
 * Usage:
 * ```
 * // Use default Halite
 * $builder = new EncryptionBuilder();
 * $adapter = $builder->build(); // Returns HaliteEncryptionAdapter
 * 
 * // Use custom adapter
 * $builder = new EncryptionBuilder();
 * $builder->withEncryptionAdapter('custom', $myAdapter);
 * $builder->useAdapter('custom');
 * $adapter = $builder->build(); // Returns $myAdapter
 * 
 * // Build multiple services
 * $builder = new EncryptionBuilder();
 * $keyFactory = $builder->buildKeyFactory();
 * $adapter = $builder->build();
 * ```
 */
final class EncryptionBuilder
{
    /** @var string Currently selected adapter name */
    private string $currentAdapter = 'halite';

    /** @var string Default adapter name */
    private string $defaultAdapter = 'halite';

    /** @var array<string, EncryptionAdapterInterface> Custom encryption adapters */
    private array $customEncryptionAdapters = [];

    /** @var array<array{name: string, adapter: KeyFactoryAdapterInterface, priority: int}> */
    private array $keyFactoryAdapters = [];

    /** @var bool Whether default adapters have been initialized */
    private bool $defaultsInitialized = false;

    /**
     * Registers a custom encryption adapter.
     * 
     * Custom adapters take precedence over built-in adapters.
     * If you register a custom adapter with name 'halite', it will
     * override the built-in Halite adapter.
     * 
     * @param string $name Adapter name (e.g., 'custom', 'halite')
     * @param EncryptionAdapterInterface $adapter Encryption adapter instance
     * @return self Fluent interface
     */
    public function withEncryptionAdapter(
        string $name,
        EncryptionAdapterInterface $adapter
    ): self {
        $this->customEncryptionAdapters[$name] = $adapter;
        return $this;
    }

    /**
     * Registers a key factory adapter.
     * 
     * Key factory adapters are used in BOTH:
     * - KeyFactory: For generating new keys (indexed by name)
     * - AdapterBasedKeyProvider: For key operations (indexed by type support)
     * 
     * @param string $name Adapter name (e.g., 'halite', 'sodium')
     * @param KeyFactoryAdapterInterface $adapter Key factory adapter instance
     * @param int $priority Priority for type-based lookup (higher = higher priority)
     * @return self Fluent interface
     */
    public function withKeyFactoryAdapter(
        string $name,
        KeyFactoryAdapterInterface $adapter,
        int $priority = 0
    ): self {
        $this->keyFactoryAdapters[] = [
            'name' => $name,
            'adapter' => $adapter,
            'priority' => $priority,
        ];

        return $this;
    }

    /**
     * Selects which adapter to use for build().
     * 
     * @param string $adapterName Adapter name to use
     * @return self Fluent interface
     * @throws \InvalidArgumentException If adapter doesn't exist
     */
    public function useAdapter(string $adapterName): self
    {
        $this->currentAdapter = $adapterName;
        return $this;
    }

    /**
     * Sets the default adapter for fallback.
     * 
     * This is used when no adapter is explicitly selected via useAdapter().
     * 
     * @param string $adapterName Default adapter name
     * @return self Fluent interface
     */
    public function withDefaultAdapter(string $adapterName): self
    {
        $this->defaultAdapter = $adapterName;
        $this->currentAdapter = $adapterName;
        return $this;
    }

    /**
     * Builds the encryption adapter.
     * 
     * Resolution order:
     * 1. Custom adapter with current name (if registered)
     * 2. Built-in adapter with current name (if exists)
     * 3. Throws exception if not found
     * 
     * @return EncryptionAdapterInterface Encryption adapter
     * @throws \InvalidArgumentException If adapter not found
     */
    public function build(): EncryptionAdapterInterface
    {
        $this->ensureDefaultsInitialized();

        // Check for custom adapter first (highest priority)
        if (isset($this->customEncryptionAdapters[$this->currentAdapter])) {
            return $this->customEncryptionAdapters[$this->currentAdapter];
        }

        // Build default/built-in adapter
        return $this->buildBuiltInAdapter($this->currentAdapter);
    }

    /**
     * Builds the KeyFactory.
     * 
     * Purpose: Generate new keys by specifying adapter NAME.
     * Registry: Simple (name → adapter)
     * 
     * The KeyFactory provides a simple interface:
     * ```
     * $key = $keyFactory->generateKey($config, 'halite');
     * ```
     * 
     * @return KeyFactoryInterface Key factory instance
     */
    public function buildKeyFactory(): KeyFactoryInterface
    {
        $this->ensureDefaultsInitialized();

        // Create simple registry indexed by adapter name
        $registry = new ServiceRegistry(KeyFactoryAdapterInterface::class);

        foreach ($this->keyFactoryAdapters as $config) {
            $registry->register($config['name'], $config['adapter']);
        }

        return new KeyFactory($registry);
    }

    /**
     * Builds an AdapterBasedKeyProvider for a specific adapter.
     * 
     * Purpose: Find adapter by key TYPE support for operations.
     * Registry: Prioritized (type → adapter)
     * 
     * This is used internally by EncryptionAdapters to convert keys
     * to library-specific formats.
     * 
     * @param string $adapterName Name of encryption adapter
     * @return AdapterBasedKeyProviderInterface Key provider instance
     */
    public function buildAdapterBasedKeyProvider(string $adapterName): AdapterBasedKeyProviderInterface
    {
        $this->ensureDefaultsInitialized();

        // Create prioritized registry for type-based lookup
        $registry = new PrioritizedServiceRegistry(KeyFactoryAdapterInterface::class);

        // Register only adapters relevant to this encryption adapter
        // In most cases, this will be just one adapter (e.g., HaliteKeyFactoryAdapter for HaliteEncryptionAdapter)
        foreach ($this->keyFactoryAdapters as $config) {
            if ($config['name'] === $adapterName) {
                $registry->register($config['adapter'], $config['priority']);
            }
        }

        return new AdapterBasedKeyProvider($registry);
    }

    /**
     * Checks if an adapter is registered (custom or built-in).
     * 
     * @param string $adapterName Adapter name to check
     * @return bool True if adapter exists
     */
    public function hasAdapter(string $adapterName): bool
    {
        // Check custom adapters
        if (isset($this->customEncryptionAdapters[$adapterName])) {
            return true;
        }

        // Check built-in adapters
        return $this->isBuiltInAdapter($adapterName);
    }

    /**
     * Gets all available adapter names.
     * 
     * @return array<string> Adapter names (custom + built-in)
     */
    public function getAvailableAdapters(): array
    {
        $custom = array_keys($this->customEncryptionAdapters);
        $builtIn = $this->getBuiltInAdapterNames();

        return array_unique(array_merge($custom, $builtIn));
    }

    /**
     * Resets the builder to initial state.
     * 
     * Useful for testing or rebuilding with different configuration.
     * 
     * @return self Fluent interface
     */
    public function reset(): self
    {
        $this->currentAdapter = 'halite';
        $this->defaultAdapter = 'halite';
        $this->customEncryptionAdapters = [];
        $this->keyFactoryAdapters = [];
        $this->defaultsInitialized = false;

        return $this;
    }

    /**
     * Ensures default adapters are initialized.
     * 
     * This is called automatically before building anything.
     * Initializes default Halite adapters if not already done.
     */
    private function ensureDefaultsInitialized(): void
    {
        if ($this->defaultsInitialized) {
            return;
        }

        // Initialize default Halite key factory adapter
        $haliteKeyFactoryAdapter = new HaliteKeyFactoryAdapter();
        
        // Only register if not already registered by user
        if (!$this->hasKeyFactoryAdapter('halite')) {
            $this->withKeyFactoryAdapter('halite', $haliteKeyFactoryAdapter, 100);
        }

        $this->defaultsInitialized = true;
    }

    /**
     * Checks if a key factory adapter is already registered.
     * 
     * @param string $name Adapter name
     * @return bool True if registered
     */
    private function hasKeyFactoryAdapter(string $name): bool
    {
        foreach ($this->keyFactoryAdapters as $config) {
            if ($config['name'] === $name) {
                return true;
            }
        }

        return false;
    }

    /**
     * Builds a built-in encryption adapter.
     * 
     * @param string $adapterName Adapter name
     * @return EncryptionAdapterInterface Built adapter
     * @throws \InvalidArgumentException If adapter not found
     */
    private function buildBuiltInAdapter(string $adapterName): EncryptionAdapterInterface
    {
        return match ($adapterName) {
            'halite' => $this->buildHaliteAdapter(),
            default => throw new \InvalidArgumentException(
                "Unknown encryption adapter '{$adapterName}'. " .
                "Available adapters: " . implode(', ', $this->getAvailableAdapters())
            ),
        };
    }

    /**
     * Builds the Halite encryption adapter.
     * 
     * @return HaliteEncryptionAdapter Halite adapter
     */
    private function buildHaliteAdapter(): HaliteEncryptionAdapter
    {
        $keyProvider = $this->buildAdapterBasedKeyProvider('halite');
        return new HaliteEncryptionAdapter($keyProvider);
    }

    /**
     * Checks if adapter name is a built-in adapter.
     * 
     * @param string $adapterName Adapter name
     * @return bool True if built-in
     */
    private function isBuiltInAdapter(string $adapterName): bool
    {
        return in_array($adapterName, $this->getBuiltInAdapterNames(), true);
    }

    /**
     * Gets list of built-in adapter names.
     * 
     * @return array<string> Built-in adapter names
     */
    private function getBuiltInAdapterNames(): array
    {
        return ['halite'];
    }
}
