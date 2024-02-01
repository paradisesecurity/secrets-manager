<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Utility;

interface UtilityInterface
{
    public static function createUniqueId(int $length = 24): string;

    public static function tempFile(string $prefix = 'secret-', string $dir = ''): string;

    public static function subString(string $str, int $start, int $length = null): string;

    public static function stringLength(string $str): int;
}
