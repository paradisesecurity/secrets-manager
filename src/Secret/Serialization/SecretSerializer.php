<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret\Serialization;

use ParadiseSecurity\Component\SecretsManager\Exception\SecretSerializationException;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;

/**
 * Handles serialization and deserialization of secret values.
 */
final class SecretSerializer
{
    public function serialize(mixed $value): string
    {
        try {
            return json_encode($value, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new SecretSerializationException(
                "Failed to serialize secret value: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    public function deserialize(string $jsonData): mixed
    {
        try {
            return json_decode($jsonData, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new SecretSerializationException(
                "Failed to deserialize secret value: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }
}
