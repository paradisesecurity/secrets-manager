<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParagonIE\HiddenString\HiddenString;

interface KeyManagerInterface
{
    public const CHECKSUM_EXTENSION = '.checksum';

    public const KEYRING_NAME = 'development';

    public const KEYRING_EXTENSION = '.keyring';

    public function setAccessor(MasterKeyProviderInterface $keyProvider, KeyManagerInterface $keyManager, string $accessor);

    public function flushVault(string $vault): void;

    public function flushKeyring(): void;

    public function getEncryptionAdapter(): EncryptionAdapterInterface;

    public function getKeyFactory(): KeyFactoryInterface;

    public function hasVault(string $vault): bool;

    public function generateKey(KeyConfigInterface $config, string $adapter = null): ?KeyInterface;

    public function getRawKeyMaterial(KeyInterface $key): HiddenString;

    public function addKey(string $vault, string $name, KeyInterface $key): void;

    public function addMetadata(string $vault, string $name, mixed $value): void;

    public function newKey(string $vault, string $name, KeyConfigInterface $config): ?KeyInterface;

    public function getKey(string $vault, string $name): ?KeyInterface;

    public function getMetadata(string $vault, string $name): mixed;

    public function addAuth(KeyInterface $authKey): KeyInterface;

    public function newAuth(): ?KeyInterface;

    public function newKeyring(KeyInterface $authKey = null): ?KeyInterface;

    public function lockKeyring(KeyInterface $authKey): void;

    public function unlockKeyring(KeyInterface $authKey): void;

    public function doesKeyringExist(): bool;

    public function loadKeyring(KeyInterface $authKey): void;

    public function saveKeyring(KeyInterface $authKey): void;
}
