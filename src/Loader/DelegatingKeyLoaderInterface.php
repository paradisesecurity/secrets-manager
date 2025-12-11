<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Loader;

use ParadiseSecurity\Component\SecretsManager\Exception\KeyLoaderException;
use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;

/**
 * Interface for delegating key loader.
 * 
 * Provides access to different key storage implementations
 * by name (e.g., 'file', 'environment', 'vault').
 * 
 * Implements Service Locator pattern for key storage backends.
 */
interface DelegatingKeyLoaderInterface
{
    /**
     * Gets a key storage loader by name.
     * 
     * @param string $loaderName Loader name (e.g., 'file', 'environment')
     * @return KeyStorageInterface Key storage implementation
     * @throws KeyLoaderException If loader not found
     */
    public function getLoader(string $loaderName): KeyStorageInterface;

    /**
     * Checks if a loader is registered.
     * 
     * @param string $loaderName Loader name
     * @return bool True if registered
     */
    public function hasLoader(string $loaderName): bool;

    /**
     * Gets all registered loader names.
     * 
     * @return array<string> Loader names
     */
    public function getLoaderNames(): array;
}
