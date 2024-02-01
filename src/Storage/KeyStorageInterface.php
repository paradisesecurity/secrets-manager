<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Storage;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

interface KeyStorageInterface
{
    public const KEY_FILE_EXTENSION = '.key';

    public const ENVIRONMENT_FILE_NAME = '.env';

    public function getName(): string;

    public function import(string $name): mixed;

    public function save(string $name, KeyInterface $key): void;

    public function resolve(string $contents): KeyInterface;
}
