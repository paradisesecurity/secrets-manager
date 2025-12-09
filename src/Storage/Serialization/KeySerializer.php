<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Storage\Serialization;

use ParadiseSecurity\Component\SecretsManager\Exception\KeySerializationException;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

use function is_array;
use function is_object;
use function is_string;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Handles serialization and deserialization of cryptographic keys.
 * Supports both JSON and line-delimited formats.
 */
final class KeySerializer
{
    /**
     * Serializes a key to JSON format.
     */
    public function serializeToJson(KeyInterface $key): string
    {
        $data = [
            'hex' => $key->getHex()->getString(),
            'type' => $key->getType(),
            'adapter' => $key->getAdapter(),
            'version' => $key->getVersion(),
        ];

        try {
            return json_encode($data, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new KeySerializationException(
                "Failed to serialize key to JSON: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Deserializes a key from JSON format.
     */
    public function deserializeFromJson(string $json): KeyInterface
    {
        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new KeySerializationException(
                "Failed to deserialize key from JSON: {$exception->getMessage()}",
                previous: $exception
            );
        }

        return $this->buildKeyFromArray($data);
    }

    /**
     * Serializes a key to line-delimited format.
     * Format: hex\ntype\nadapter\nversion
     */
    public function serializeToLines(KeyInterface $key): string
    {
        return implode(PHP_EOL, [
            $key->getHex()->getString(),
            $key->getType(),
            $key->getAdapter(),
            $key->getVersion(),
        ]);
    }

    /**
     * Deserializes a key from line-delimited format.
     */
    public function deserializeFromLines(string $content): KeyInterface
    {
        $lines = explode(PHP_EOL, $content, 4);

        if (count($lines) !== 4) {
            throw new KeySerializationException(
                'Invalid line-delimited key format. Expected 4 lines (hex, type, adapter, version).'
            );
        }

        return new Key(
            new HiddenString($lines[0]),
            $lines[1],
            $lines[2],
            $lines[3]
        );
    }

    /**
     * Attempts to deserialize from any supported format.
     * Tries JSON first, then falls back to line-delimited.
     */
    public function deserializeAuto(string $content): KeyInterface
    {
        // Try JSON first
        if ($this->looksLikeJson($content)) {
            try {
                return $this->deserializeFromJson($content);
            } catch (KeySerializationException) {
                // Fall through to try line-delimited
            }
        }

        // Try line-delimited format
        return $this->deserializeFromLines($content);
    }

    /**
     * Normalizes various input formats to array for key building.
     */
    public function normalizeToArray(mixed $data): array
    {
        if (is_string($data)) {
            try {
                $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                throw new KeySerializationException('Invalid key data format.');
            }
        }

        if (is_object($data)) {
            $data = (array) $data;
        }

        if (!is_array($data)) {
            throw new KeySerializationException(
                sprintf('Unable to normalize key data of type "%s".', gettype($data))
            );
        }

        return $data;
    }

    private function buildKeyFromArray(array $data): KeyInterface
    {
        $this->validateKeyData($data);

        return new Key(
            new HiddenString($data['hex']),
            $data['type'],
            $data['adapter'],
            $data['version']
        );
    }

    private function validateKeyData(array $data): void
    {
        $requiredFields = ['hex', 'type', 'adapter', 'version'];
        
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new KeySerializationException(
                    "Missing required field '{$field}' in key data"
                );
            }
        }
    }

    private function looksLikeJson(string $content): bool
    {
        $trimmed = trim($content);
        return (
            (str_starts_with($trimmed, '{') && str_ends_with($trimmed, '}')) ||
            (str_starts_with($trimmed, '[') && str_ends_with($trimmed, ']'))
        );
    }
}
