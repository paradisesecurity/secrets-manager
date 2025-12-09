<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParagonIE\HiddenString\HiddenString;

/**
 * Immutable cryptographic key value object.
 */
readonly final class Key implements KeyInterface
{
    private KeyType $type;

    public function __construct(
        private HiddenString $hex,
        KeyType|string $type,
        private string $adapter,
        private string $version,
    ) {
        if (is_string($type)) {
            $this->type = KeyType::fromString($type);
        }
    }

    public function getHex(): HiddenString
    {
        return $this->hex;
    }

    public function getType(): string
    {
        return $this->type->toString();
    }

    public function getAdapter(): string
    {
        return $this->adapter;
    }

    public function getVersion(): string
    {
        return $this->version;
    }
}
