<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter;

/**
 * Base interface for all operational adapters.
 * 
 * Provides common methods for adapter identification and versioning.
 * All adapters (except filesystem adapters) should implement this interface
 * either directly or through AbstractAdapter.
 * 
 * Types of adapters:
 * - Encryption adapters: Wrap different encryption libraries
 * - Key factory adapters: Generate keys for different encryption systems
 * - Vault adapters: Handle different secret storage formats
 */
interface AbstractAdapterInterface
{
    /**
     * Gets the unique identifier for this adapter.
     * 
     * Examples: 'halite', 'sodium', 'openssl', 'json_vault'
     * 
     * @return string The adapter name
     */
    public function getName(): string;

    /**
     * Gets the version of the underlying library or implementation.
     * 
     * This helps track compatibility and handle version-specific behavior.
     * 
     * @return string Version string (e.g., '5.0.0', '1.0.18')
     */
    public function getVersion(): string;

    /**
     * Sets the adapter name.
     * 
     * Typically called during adapter initialization.
     * 
     * @param string $name Adapter name
     * @return void
     */
    public function setName(string $name): void;

    /**
     * Sets the adapter version.
     * 
     * @param string $version Version string
     * @return void
     */
    public function setVersion(string $version): void;
}
