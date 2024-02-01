<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParagonIE\HiddenString\HiddenString;

final class Key implements KeyInterface
{
    public function __construct(
        private HiddenString $hex,
        private string $type,
        private string $adapter,
        private string $version,
    ) {
    }

    public function getHex(): HiddenString
    {
        return $this->hex;
    }

    public function getType(): string
    {
        return $this->type;
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
