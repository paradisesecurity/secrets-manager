<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

final class ChainVaultAdapter extends AbstractVaultAdapter
{
    private array $adapters = [];

    public function __construct(array $adapters)
    {
        foreach ($adapters as $adapter) {
            if ($adapter instanceof VaultAdapterInterface) {
                $this->adapters[] = $adapter;
            }
        }
    }

    public function getSecret(string $key, array $options = []): SecretInterface
    {
        foreach ($this->adapters as $index => $adapter) {
            try {
                return $adapter->getSecret($key, $options[$index] ?? $options);
            } catch (SecretNotFoundException $ignored) {
                continue;
            }
        }

        throw SecretNotFoundException::withKey($key);
    }

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        foreach ($this->adapters as $index => $adapter) {
            $adapter->putSecret($secret, $options[$index] ?? $options);
        }

        return $secret;
    }

    public function deleteVault(array $options = []): void
    {
        foreach ($this->adapters as $index => $adapter) {
            $adapter->deleteVault($options[$index] ?? $options);
        }
    }

    public function deleteSecret(SecretInterface $secret, array $options = []): void
    {
        foreach ($this->adapters as $index => $adapter) {
            $adapter->deleteSecret($secret, $options[$index] ?? $options);
        }
    }

    public function deleteSecretByKey(string $key, array $options): void
    {
        $success = false;
        foreach ($this->adapters as $index => $adapter) {
            try {
                $adapter->deleteSecret($adapter->getSecret($key), $options[$index] ?? $options);
                $success = true;
            } catch (SecretNotFoundException $ignored) {
                continue;
            }
        }

        if (!$success) {
            throw SecretNotFoundException::withKey($key);
        }
    }

    public function configureSharedOptions(OptionsResolver $resolver): void
    {
        parent::configureSharedOptions($resolver);

        foreach ($this->adapters as $index => $adapter) {
            $adapter->configureSharedOptions($resolver);
        }
    }

    public function configureGetSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureGetSecretOptions($resolver);

        foreach ($this->adapters as $index => $adapter) {
            $adapter->configureGetSecretOptions($resolver);
        }
    }

    public function configurePutSecretOptions(OptionsResolver $resolver): void
    {
        parent::configurePutSecretOptions($resolver);

        foreach ($this->adapters as $index => $adapter) {
            $adapter->configurePutSecretOptions($resolver);
        }
    }

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureDeleteSecretOptions($resolver);

        foreach ($this->adapters as $index => $adapter) {
            $adapter->configureDeleteSecretOptions($resolver);
        }
    }
}
