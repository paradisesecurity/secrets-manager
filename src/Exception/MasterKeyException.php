<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

/**
 * Exception thrown when master key operations fail.
 */
class MasterKeyException extends \RuntimeException
{
    public static function missingKey(string $keyName): self
    {
        return new self(
            "Required master key '{$keyName}' is missing. " .
            "Master keys must be loaded before the application can start."
        );
    }

    public static function missingSignatureKeys(): self
    {
        return new self(
            "Missing signature keys. Either a signature key pair OR " .
            "both signature secret and public keys must be provided."
        );
    }

    public static function invalidKeyType(string $keyType): self
    {
        return new self(
            "Invalid master key type '{$keyType}'. " .
            "Master keys must be symmetric encryption keys or asymmetric signature keys."
        );
    }

    public static function loaderFailed(string $loaderName, \Exception $previous): self
    {
        return new self(
            "Failed to get key loader '{$loaderName}': {$previous->getMessage()}",
            0,
            $previous
        );
    }

    public static function keyNotAvailable(string $keyName): self
    {
        return new self(
            "Master key '{$keyName}' is not available. " .
            "Check that keys are properly configured and loaded."
        );
    }
}
