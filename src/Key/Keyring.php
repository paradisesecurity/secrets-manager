<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use JsonSerializable;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToAccessRestrictedCommandsException;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;
use ParagonIE\HiddenString\HiddenString;

use function array_diff_key;
use function array_fill;
use function array_flip;
use function array_key_exists;
use function array_merge;
use function in_array;
use function is_null;

final class Keyring implements KeyringInterface, JsonSerializable
{
    private string $uniqueId;

    private bool $locked = false;

    private array $vault = [];

    private array $macs = [];

    public function __construct()
    {
        $this->uniqueId = Utility::createUniqueId(KeyringInterface::UNIQUE_ID_LENGTH);
    }

    public function getUniqueId(): string
    {
        return $this->uniqueId;
    }

    public function hasVault(string $vault): bool
    {
        return array_key_exists($vault, $this->vault);
    }

    public function hasKey(string $vault, string $name): bool
    {
        if (!$this->hasVault($vault)) {
            return false;
        }

        return array_key_exists($name, $this->vault[$vault]);
    }

    public function hasMetadata(string $vault, string $name): bool
    {
        if (!$this->hasKey($vault, 'metadata')) {
            return false;
        }

        return array_key_exists($name, $this->vault[$vault]['metadata']);
    }

    public function getKeys(string $vault): array
    {
        if ($this->isLocked() === true) {
            return [];
        }

        if (!array_key_exists($vault, $this->vault)) {
            return [];
        }

        $keys = [];

        foreach ($this->vault[$vault] as $name) {
            $key = $this->getKey($vault, $name);
            if (is_null($key)) {
                continue;
            }
            $keys[] = $key;
        }

        return $keys;
    }

    public function getKey(string $vault, string $name): ?KeyInterface
    {
        if ($this->hasKey($vault, $name)) {
            $keyHolder = $this->vault[$vault][$name];

            return $this->extractKeyFromKeyHolder($keyHolder);
        }

        return null;
    }

    private function extractKeyFromKeyHolder(array $keyHolder): ?KeyInterface
    {
        if (empty($keyHolder)) {
            return null;
        }

        $required = ['hex', 'type', 'adapter', 'version'];
        if (array_diff_key(array_flip($required), $keyHolder)) {
            return null;
        }

        $hex = $keyHolder['hex'];
        $type = $keyHolder['type'];
        $adapter = $keyHolder['adapter'];
        $version = $keyHolder['version'];

        return new Key(new HiddenString($hex), $type, $adapter, $version);
    }

    public function addKey(string $vault, string $name, KeyInterface $key): void
    {
        if ($this->isLocked() === true) {
            return;
        }

        $this->addVerifiedKey($vault, $name, $this->getKeyHolder($key));
    }

    public function getMetadata(string $vault, string $name): mixed
    {
        if ($this->hasMetadata($vault, $name)) {
            return $this->vault[$vault]['metadata'][$name];
        }

        return null;
    }

    public function addMetadata(string $vault, string $name, mixed $value): void
    {
        if ($this->isLocked() === true) {
            return;
        }

        $this->vault[$vault]['metadata'][$name] = $value;
    }

    private function getKeyHolder(KeyInterface $key): array
    {
        $keyHolder = [];

        $keyHolder['hex'] = $key->getHex()->getString();
        $keyHolder['type'] = $key->getType();
        $keyHolder['adapter'] = $key->getAdapter();
        $keyHolder['version'] = $key->getVersion();

        return $keyHolder;
    }

    private function addVerifiedKey(string $vault, string $name, array $keyHolder): void
    {
        if (!empty($keyHolder)) {
            $this->vault[$vault][$name] = $keyHolder;
        }
    }

    public function removeKey(string $vault, string $name): void
    {
        if ($this->isLocked() === true) {
            return;
        }

        if ($this->vault[$vault][$name]) {
            unset($this->vault[$vault][$name]);
        }
    }

    public function flushKeys(string $vault): void
    {
        if ($this->isLocked() === true) {
            return;
        }

        $this->vault[$vault] = [];
        unset($this->vault[$vault]);
    }

    public function flushVault(): void
    {
        if ($this->isLocked() === true) {
            return;
        }

        foreach ($this->vault as $vault) {
            $this->flushKeys($vault);
        }

        $this->vault = [];
    }

    public function flushAuth(): void
    {
        if ($this->isLocked() === true) {
            return;
        }

        $this->macs = [];
    }

    public function isLocked(): bool
    {
        return ($this->locked === true);
    }

    public function lock(string $mac): void
    {
        if ($this->hasAccess($mac)) {
            $this->locked = true;
            return;
        }

        throw new UnableToAccessRestrictedCommandsException();
    }

    public function unlock(string $mac): void
    {
        if ($this->hasAccess($mac) === true) {
            $this->locked = false;
            return;
        }

        throw new UnableToAccessRestrictedCommandsException();
    }

    public function addAuth(string $mac): void
    {
        if ($this->isLocked() === true) {
            return;
        }

        $this->macs[] = $mac;
    }

    public function jsonSerialize(): mixed
    {
        return [
            'locked' => true,
            'vault' => $this->vault,
            'uniqueId' => $this->uniqueId,
            'macs' => $this->macs,
        ];
    }

    public function hasAccess(string $mac): bool
    {
        return in_array($mac, $this->macs, true);
    }

    public function withSecuredData(string $uniqueId, array $vault = [], array $macs = []): self
    {
        $this->locked = true;
        $this->vault = $vault;
        $this->uniqueId = $uniqueId;
        $this->macs = $macs;

        return $this;
    }
}
