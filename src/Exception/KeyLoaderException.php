<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

/**
 * Exception thrown when key loader operations fail.
 */
class KeyLoaderException extends \RuntimeException
{
    public static function loaderNotFound(string $loaderName, array $availableLoaders): self
    {
        $available = empty($availableLoaders)
            ? 'none'
            : implode(', ', $availableLoaders);

        return new self(
            "Key loader '{$loaderName}' not found. " .
            "Available loaders: {$available}"
        );
    }

    public static function noLoadersConfigured(): self
    {
        return new self(
            'No key loaders configured. ' .
            'Register at least one key storage loader (file, environment, etc.).'
        );
    }
}
