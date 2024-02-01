<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParagonIE\HiddenString\HiddenString;

interface KeyInterface
{
    public function getHex(): HiddenString;

    public function getType(): string;

    public function getAdapter(): string;

    public function getVersion(): string;
}
