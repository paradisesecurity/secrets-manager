<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter;

interface AbstractAdapterInterface
{
    public function getName(): string;

    public function setName(string $name): void;

    public function getVersion(): string;

    public function setVersion(string $version): void;
}
