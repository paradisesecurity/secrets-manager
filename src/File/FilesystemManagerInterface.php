<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

interface FilesystemManagerInterface
{
    public const KEYRING = 'keyring';

    public const ENVIRONMENT = 'environment';

    public const CHECKSUM = 'checksum';

    public const MASTER_KEYS = 'master_keys';

    public const VAULT = 'vault';

    public function getDefaultConnections(): array;

    public function setEnvironment(?string $environment): void;

    public function getEnvironment(): ?string;

    public function getPath(string $path): string;

    public function hasConnection(string $connection): bool;

    public function createConnection(string $connection): void;

    public function removeConnection(string $connection): void;

    public function insert(FilesystemAdapterInterface $adapter, string $connection, int $priority = 0): void;

    public function getFilesystem(string $connection, string $path = null): FilesystemAdapterInterface;
}
