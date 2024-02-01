<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Trait;

interface ConfigurationAwareInterface
{
    public function hasOption(string $key): bool;

    public function getOption(string $key): mixed;

    public function getOptions(): array;

    public function addOption(string $key, mixed $value): self;

    public function addOptions(array $options): self;

    public function getConfig(string $key): mixed;

    public function getConfiguration(): array;
}
