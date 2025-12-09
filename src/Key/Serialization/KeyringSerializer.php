<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key\Serialization;

use ParadiseSecurity\Component\SecretsManager\Exception\KeyringSerializationException;
use ParadiseSecurity\Component\SecretsManager\Key\Keyring;
use ParadiseSecurity\Component\SecretsManager\Key\KeyringInterface;

use function json_decode;
use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;

/**
 * Handles keyring serialization/deserialization.
 * Clean separation of concerns from KeyManager.
 */
final class KeyringSerializer
{
    public function serialize(KeyringInterface $keyring): string
    {
        try {
            return json_encode($keyring, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new KeyringSerializationException(
                "Failed to serialize keyring: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    public function deserialize(string $jsonData): KeyringInterface
    {
        try {
            $data = json_decode($jsonData, true, 512, JSON_THROW_ON_ERROR);
            
            $this->validateKeyringData($data);
            
            $keyring = new Keyring();
            return $keyring->withSecuredData(
                $data['uniqueId'],
                $data['vault'],
                $data['macs']
            );
        } catch (\JsonException $exception) {
            throw new KeyringSerializationException(
                "Failed to deserialize keyring: Invalid JSON - {$exception->getMessage()}",
                previous: $exception
            );
        } catch (\Exception $exception) {
            throw new KeyringSerializationException(
                "Failed to deserialize keyring: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    private function validateKeyringData(mixed $data): void
    {
        if (!is_array($data)) {
            throw new KeyringSerializationException('Keyring data must be an array');
        }

        $requiredFields = ['uniqueId', 'vault', 'macs'];
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new KeyringSerializationException(
                    "Missing required field '{$field}' in keyring data"
                );
            }
        }
    }
}
