<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Interface for vault adapters.
 * 
 * Vault adapters provide abstraction for different secret storage mechanisms:
 * - FilesystemVaultAdapter: JSON files on disk
 * - PSR6CacheVaultAdapter: Decorator adding cache layer
 * - ChainVaultAdapter: Chain of Responsibility for multiple backends
 * 
 * This allows secrets to be stored in various backends (files, databases,
 * cloud services) with optional caching and failover support.
 * 
 * Design Patterns Used:
 * - Strategy: Different storage implementations
 * - Decorator: PSR6CacheVaultAdapter wraps other adapters
 * - Chain of Responsibility: ChainVaultAdapter tries adapters in sequence
 * - Composite: ChainVaultAdapter manages multiple adapters
 */
interface VaultAdapterInterface
{
    /**
     * Retrieves a secret by its key.
     * 
     * @param string $key Secret identifier (unique ID)
     * @param array $options Configuration options (vault name, path, etc.)
     * @return SecretInterface The retrieved secret
     * @throws SecretNotFoundException If secret not found
     */
    public function getSecret(string $key, array $options = []): SecretInterface;

    /**
     * Stores a secret in the vault.
     * 
     * Creates a new secret or updates an existing one.
     * 
     * @param SecretInterface $secret Secret to store
     * @param array $options Configuration options
     * @return SecretInterface The stored secret (may be modified)
     */
    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface;

    /**
     * Deletes a secret from the vault.
     * 
     * @param SecretInterface $secret Secret to delete
     * @param array $options Configuration options
     * @return void
     * @throws SecretNotFoundException If secret not found
     */
    public function deleteSecret(SecretInterface $secret, array $options = []): void;

    /**
     * Deletes a secret by its key.
     * 
     * Convenience method that doesn't require loading the full secret.
     * 
     * @param string $key Secret identifier
     * @param array $options Configuration options
     * @return void
     * @throws SecretNotFoundException If secret not found
     */
    public function deleteSecretByKey(string $key, array $options): void;

    /**
     * Deletes an entire vault.
     * 
     * WARNING: This operation is destructive and may not be reversible.
     * 
     * @param array $options Configuration options (must include delete_all or delete_vault flags)
     * @return void
     */
    public function deleteVault(array $options = []): void;

    /**
     * Configures options shared across all operations.
     * 
     * Common options:
     * - vault: Vault name (required)
     * - path: Custom path to vault file
     * 
     * @param OptionsResolver $resolver Symfony OptionsResolver
     * @return void
     */
    public function configureSharedOptions(OptionsResolver $resolver): void;

    /**
     * Configures options specific to getSecret operations.
     * 
     * @param OptionsResolver $resolver Symfony OptionsResolver
     * @return void
     */
    public function configureGetSecretOptions(OptionsResolver $resolver): void;

    /**
     * Configures options specific to putSecret operations.
     * 
     * @param OptionsResolver $resolver Symfony OptionsResolver
     * @return void
     */
    public function configurePutSecretOptions(OptionsResolver $resolver): void;

    /**
     * Configures options specific to deleteSecret operations.
     * 
     * Common options:
     * - delete_all: Delete from all adapters in chain
     * - delete_vault: Delete entire vault file
     * - clear_cache: Clear cache entries
     * 
     * @param OptionsResolver $resolver Symfony OptionsResolver
     * @return void
     */
    public function configureDeleteSecretOptions(OptionsResolver $resolver): void;
}
