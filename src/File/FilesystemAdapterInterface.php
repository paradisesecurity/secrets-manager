<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

interface FilesystemAdapterInterface
{
    public function has(string $path): bool;

    public function read(string $path): string;

    public function open(string $path): mixed;

    public function close(string $path): void;

    public function save(string $path, string $contents, array $config = []): void;

    public function write(string $path, string $stream, array $config = []): void;

    public function delete(string $path): void;

    public function mkdir(string $path, array $config = []): void;

    public function permission(string $path, string $permission): bool;

    public function chmod(string $path, string $visibility): void;

    public function realpath(string $path = ''): string;
}
