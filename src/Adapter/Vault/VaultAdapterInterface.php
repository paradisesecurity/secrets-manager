<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use Symfony\Component\OptionsResolver\OptionsResolver;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;

interface VaultAdapterInterface
{
    public function getSecret(string $key, array $options = []): SecretInterface;

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface;

    public function deleteSecret(SecretInterface $secret, array $options = []): void;

    public function deleteVault(array $options = []): void;

    public function deleteSecretByKey(string $key, array $options): void;

    public function configureSharedOptions(OptionsResolver $resolver): void;

    public function configureGetSecretOptions(OptionsResolver $resolver): void;

    public function configurePutSecretOptions(OptionsResolver $resolver): void;

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void;
}
