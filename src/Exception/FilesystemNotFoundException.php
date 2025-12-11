<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class FilesystemNotFoundException extends \RuntimeException
{
    public static function noAdapters(string $connection): self
    {
        return new self(
            "No filesystem adapters registered for connection '{$connection}'."
        );
    }

    public static function pathNotFound(string $path, string $connection): self
    {
        return new self(
            "Path '{$path}' not found in any adapter for connection '{$connection}'."
        );
    }

    public static function connectionNotFound(string $connection): self
    {
        return new self(
            "Connection '{$connection}' does not exist."
        );
    }
}
