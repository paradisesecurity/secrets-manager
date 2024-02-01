<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManager;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\VaultAdapterInterface;

final class SecretManagerBuilder
{
    private VaultAdapterInterface $adapter;

    private KeyManagerInterface $manager;

    private KeyInterface $auth;

    private string $vault = '';

    private array $options = [];

    public function __construct()
    {
    }

    public function withVaultAdapter(VaultAdapterInterface $adapter): self
    {
        $this->adapter = $adapter;

        return $this;
    }

    public function withKeyManager(KeyManagerInterface $manager): self
    {
        $this->manager = $manager;

        return $this;
    }

    public function withAuthKey(KeyInterface $auth): self
    {
        $this->auth = $auth;

        return $this;
    }

    public function withVault(string $vault): self
    {
        $this->vault = $vault;

        return $this;
    }

    public function withOptions(array $options): self
    {
        $this->options = $options;

        return $this;
    }

    public function withOption(string $key, mixed $value): self
    {
        $this->options[$key] = $value;

        return $this;
    }

    public function build(): SecretManagerInterface
    {
        return new SecretManager(
            $this->adapter,
            $this->manager,
            $this->auth,
            $this->vault,
            $this->options
        );
    }
}
