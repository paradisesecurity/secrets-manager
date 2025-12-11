<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

/**
 * Exception thrown when an encryption request is invalid.
 * 
 * This indicates a precondition violation - the request doesn't
 * meet the requirements for the operation.
 */
class InvalidEncryptionRequestException extends \InvalidArgumentException
{
    public static function missingKeys(string $operation): self
    {
        return new self(
            "Operation '{$operation}' requires encryption keys, but none were provided."
        );
    }

    public static function missingOutputFile(string $operation): self
    {
        return new self(
            "Operation '{$operation}' requires an output file, but none was provided."
        );
    }

    public static function invalidKeyType(string $operation, array $expected, string $actual): self
    {
        $expectedList = implode(', ', $expected);
        return new self(
            "Operation '{$operation}' expected key types [{$expectedList}], but got '{$actual}'."
        );
    }
}
