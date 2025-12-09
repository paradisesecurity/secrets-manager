<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret;

use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\VaultAdapterInterface;

interface SecretManagerInterface
{
    public function newVault(string $vault): void;

    public function getSecret(string $key, array $options = []): SecretInterface;

    public function get(string $key): mixed;

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface;

    public function set(string $key, mixed $value): bool;

    public function deleteSecretByKey(string $key, array $options = []): void;

    public function deleteSecret(SecretInterface $secret, array $options = []): void;

    public function delete(string $key): bool;

    public function vault(string $vault): self;

    public function options(array $options): self;

    public function getVaultAdapter(): VaultAdapterInterface;

    public function rotateSecrets(string $vault, array $secretKeys = []): bool;
}
