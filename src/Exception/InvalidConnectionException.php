<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

/**
 * Exception thrown when filesystem connection operations fail.
 */
class InvalidConnectionException extends \InvalidArgumentException
{
    public static function connectionNotFound(string $connection): self
    {
        return new self("Connection '{$connection}' does not exist.");
    }

    public static function connectionAlreadyExists(string $connection): self
    {
        return new self("Connection '{$connection}' already exists.");
    }

    public static function cannotRemoveDefaultConnection(string $connection): self
    {
        return new self(
            "Cannot remove default connection '{$connection}'. " .
            "Default connections are required for system operation."
        );
    }

    public static function noAdaptersRegistered(string $connection): self
    {
        return new self(
            "No filesystem adapters registered for connection '{$connection}'. " .
            "Register at least one adapter before using this connection."
        );
    }
}
