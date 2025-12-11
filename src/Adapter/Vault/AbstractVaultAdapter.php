<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Abstract base for vault adapters.
 * 
 * Provides default option configuration that all adapters share.
 * Concrete adapters should extend this and implement VaultAdapterInterface.
 */
abstract class AbstractVaultAdapter implements VaultAdapterInterface
{
    /**
     * Configures the 'vault' option required by all adapters.
     */
    public function configureSharedOptions(OptionsResolver $resolver): void
    {
        $resolver->setIgnoreUndefined(true);

        if (!$resolver->isDefined('vault')) {
            $resolver->define('vault')
                ->allowedTypes('string')
                ->required()
                ->info('The name of the vault');
        }
    }

    /**
     * Default implementation has no additional options.
     * Override in concrete classes to add specific options.
     */
    public function configureGetSecretOptions(OptionsResolver $resolver): void
    {
        // Default: no additional options
    }

    /**
     * Default implementation has no additional options.
     * Override in concrete classes to add specific options.
     */
    public function configurePutSecretOptions(OptionsResolver $resolver): void
    {
        // Default: no additional options
    }

    /**
     * Configures the 'delete_all' option for cascading deletes.
     */
    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        if (!$resolver->isDefined('delete_all')) {
            $resolver->define('delete_all')
                ->allowedTypes('bool')
                ->default(false)
                ->info('Delete the secret from all adapters in chain');
        }
    }
}
