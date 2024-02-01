<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Utility;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;

use function ceil;
use function random_bytes;

final class Utility implements UtilityInterface
{
    public static function createUniqueId(int $length = 24): string
    {
        $byteLength = (int) ceil($length * 0.75);
        $random = random_bytes($byteLength);
        return Binary::safeSubstr(
            Base64UrlSafe::encode($random),
            0,
            $length
        );
    }

    public static function tempFile(
        string $prefix = 'secret-',
        string $dir = ''
    ): string {
        if (empty($dir)) {
            $dir = \sys_get_temp_dir();
        }
        $temp = \tempnam($dir, $prefix);
        \unlink($temp);
        return $temp;
    }

    public static function subString(
        string $str,
        int $start,
        int $length = null
    ): string {
        try {
            return Binary::safeSubstr($str, $start, $length);
        } catch (\Throwable $ex) {
            return '';
        }
    }

    public static function stringLength(string $str): int
    {
        return Binary::safeStrlen($str);
    }
}
