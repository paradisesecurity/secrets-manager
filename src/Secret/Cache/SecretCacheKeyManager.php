<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret\Cache;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;

use const SODIUM_CRYPTO_SHORTHASH_KEYBYTES;

/**
 * Manages cache key generation for secret lookup optimization.
 */
final class SecretCacheKeyManager
{
    /**
     * Generates a short hash MAC (SHM) key for efficient secret lookup.
     * Uses two-part hashing for enhanced security.
     */
    public function generateSHMKey(string $vault, string $lookup, string $cacheKeyL, string $cacheKeyR): string
    {
        // Decode base64-encoded keys before use [web:59]
        $decodedKeyL = Base64UrlSafe::decode($cacheKeyL);
        $decodedKeyR = Base64UrlSafe::decode($cacheKeyR);

        $leftHash = \sodium_crypto_shorthash($vault . $lookup, $decodedKeyL);
        $rightHash = \sodium_crypto_shorthash($vault . $lookup, $decodedKeyR);

        return Base64UrlSafe::encode($leftHash . $rightHash);
    }

    /**
     * Splits a cache key into left and right components for storage.
     */
    public function splitCacheKey(string $rawCacheKey): array
    {
        $cacheKeyL = Binary::safeSubstr($rawCacheKey, 0, SODIUM_CRYPTO_SHORTHASH_KEYBYTES);
        $cacheKeyR = Binary::safeSubstr($rawCacheKey, SODIUM_CRYPTO_SHORTHASH_KEYBYTES, SODIUM_CRYPTO_SHORTHASH_KEYBYTES);

        return [
            'cache_key_l' => Base64UrlSafe::encode($cacheKeyL),
            'cache_key_r' => Base64UrlSafe::encode($cacheKeyR),
        ];
    }
}
