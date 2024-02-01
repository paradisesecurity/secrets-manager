<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret;

use Symfony\Component\OptionsResolver\OptionsResolver;

abstract class AbstractVaultAdapter implements VaultAdapterInterface
{
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

    public function configureGetSecretOptions(OptionsResolver $resolver): void
    {
    }

    public function configurePutSecretOptions(OptionsResolver $resolver): void
    {
    }

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        if (!$resolver->isDefined('delete_all')) {
            $resolver->define('delete_all')
                ->allowedTypes('bool')
                ->required()
                ->default(false)
                ->info('Delete the vault from all adapters');
        }
    }
}
