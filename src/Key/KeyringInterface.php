<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

interface KeyringInterface
{
    public const UNIQUE_ID_LENGTH = 64;

    public function getUniqueId(): string;

    public function getKeys(string $vault): array;

    public function getKey(string $vault, string $name): ?KeyInterface;

    public function addKey(string $vault, string $name, KeyInterface $key): void;

    public function removeKey(string $vault, string $name): void;

    public function flushKeys(string $vault): void;

    public function flushVault(): void;

    public function flushAuth(): void;

    public function isLocked(): bool;

    public function lock(string $mac): void;

    public function unlock(string $mac): void;

    public function addAuth(string $mac): void;

    public function hasAccess(string $mac): bool;

    public function withSecuredData(string $uniqueId, array $vault = [], array $macs = []): self;
}
