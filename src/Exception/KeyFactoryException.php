<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

/**
 * Exception thrown when key factory operations fail.
 */
class KeyFactoryException extends \RuntimeException
{
    public static function adapterNotFound(string $adapterName, array $availableAdapters): self
    {
        $available = empty($availableAdapters)
            ? 'none'
            : implode(', ', $availableAdapters);

        return new self(
            "Key factory adapter '{$adapterName}' not found. " .
            "Available adapters: {$available}"
        );
    }

    public static function generationFailed(
        string $keyType,
        string $adapterName,
        \Exception $previous
    ): self {
        return new self(
            "Failed to generate key of type '{$keyType}' using adapter '{$adapterName}': " .
            $previous->getMessage(),
            0,
            $previous
        );
    }

    public static function unsupportedKeyType(string $keyType, array $supportedTypes): self
    {
        $supported = empty($supportedTypes)
            ? 'none'
            : implode(', ', $supportedTypes);

        return new self(
            "No adapter supports key type '{$keyType}'. " .
            "Supported types: {$supported}"
        );
    }

    public static function notAKeyPair(string $keyType): self
    {
        return new self(
            "Key type '{$keyType}' is not a key pair and cannot be split."
        );
    }

    public static function splitFailed(string $keyType, \Exception $previous): self
    {
        return new self(
            "Failed to split key pair of type '{$keyType}': {$previous->getMessage()}",
            0,
            $previous
        );
    }
}
