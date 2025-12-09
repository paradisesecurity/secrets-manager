<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistry;
use ParadiseSecurity\Component\ServiceRegistry\Registry\PrioritizedServiceRegistry;
use \ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\HaliteKeyFactoryAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactory;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\HaliteEncryptionAdapter;

/**
 * Sub-builder for encryption adapter configuration.
 */
final class EncryptionBuilder
{
    private string $adapter = 'halite';
    private array $customAdapters = [];

    public function useAdapter(string $adapter): self
    {
        $this->adapter = $adapter;
        return $this;
    }

    public function registerCustomAdapter(string $name, object $adapter): self
    {
        $this->customAdapters[$name] = $adapter;
        return $this;
    }

    public function build(): EncryptionAdapterInterface
    {
        // Check for custom adapter first
        if (isset($this->customAdapters[$this->adapter])) {
            return $this->customAdapters[$this->adapter];
        }

        // Build default adapters
        return match ($this->adapter) {
            'halite' => $this->buildHaliteAdapter(),
            default => throw new \InvalidArgumentException("Unknown encryption adapter: {$this->adapter}"),
        };
    }

    public function buildKeyFactory(): KeyFactoryInterface
    {
        $haliteKeyFactoryAdapter = new HaliteKeyFactoryAdapter();

        $factoryRegistry = new ServiceRegistry(
            KeyFactoryAdapterInterface::class
        );
        $factoryRegistry->register('halite', $haliteKeyFactoryAdapter);

        return new KeyFactory($factoryRegistry);
    }

    private function buildHaliteAdapter(): EncryptionAdapterInterface
    {
        $haliteKeyFactoryAdapter = new HaliteKeyFactoryAdapter();

        $adapterRegistry = new PrioritizedServiceRegistry(
            KeyFactoryAdapterInterface::class
        );
        $adapterRegistry->register($haliteKeyFactoryAdapter);

        $adapterBasedKeyProvider = new AdapterBasedKeyProvider($adapterRegistry);

        return new HaliteEncryptionAdapter($adapterBasedKeyProvider);
    }
}
