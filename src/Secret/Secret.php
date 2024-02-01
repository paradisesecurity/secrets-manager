<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret;

use JsonSerializable;

use function array_key_exists;
use function is_array;

class Secret implements SecretInterface, JsonSerializable
{
    private ?array $metadata;

    public function __construct(
        private string $uniqueId,
        private string $key,
        private array|string $value,
        private bool $encrypted = false,
        ?array $metadata = null,
    ) {
        $this->metadata = $metadata;
    }

    public function getUniqueId(): string
    {
        return $this->uniqueId;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getValue(): array|string
    {
        return $this->value;
    }

    public function getMetadata(): array
    {
        return $this->metadata ?? [];
    }

    public function isEncrypted(): bool
    {
        return $this->encrypted;
    }

    public function has(string|int $index): bool
    {
        return is_array($this->value) && array_key_exists($index, $this->value);
    }

    public function get(string|int $index): mixed
    {
        if (!$this->has($index)) {
            return null;
        }

        return $this->value[$index];
    }

    public function jsonSerialize(): mixed
    {
        return [
            'key' => $this->key,
            'value' => $this->value,
            'uniqueId' => $this->uniqueId,
            'encrypted' => $this->encrypted,
            'metadata' => $this->metadata,
        ];
    }

    public function withEncryptedValue(string|array $value): self
    {
        return new self($this->uniqueId, $this->key, $value, true, $this->metadata);
    }

    public function withDecryptedValue(string|array $value): self
    {
        return new self($this->uniqueId, $this->key, $value, false, $this->metadata);
    }

    public function withMetadata(array $metadata): self
    {
        return new self($this->uniqueId, $this->key, $this->value, $this->encrypted, $metadata);
    }
}
