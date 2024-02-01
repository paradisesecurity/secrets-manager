<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret;

interface SecretInterface
{
    public function getKey(): string;

    public function getValue(): array|string;

    public function getMetadata(): array;

    public function isEncrypted(): bool;

    public function has(string|int $index): bool;

    public function get(string|int $index): mixed;

    public function withEncryptedValue(string|array $value): self;

    public function withDecryptedValue(string|array $value): self;

    public function withMetadata(array $metadata): self;
}
