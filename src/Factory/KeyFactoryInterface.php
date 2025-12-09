<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Factory;

use ParadiseSecurity\Component\SecretsManager\Key\KeyTypeConstants;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;

interface KeyFactoryInterface
{
    // Reference the central values - defined once, used everywhere
    public const ASYMMETRIC_ENCRYPTION_KEY_PAIR = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_KEY_PAIR;
    public const ASYMMETRIC_ENCRYPTION_PUBLIC_KEY = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY;
    public const ASYMMETRIC_ENCRYPTION_SECRET_KEY = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_SECRET_KEY;
    public const ASYMMETRIC_SIGNATURE_KEY_PAIR = KeyTypeConstants::ASYMMETRIC_SIGNATURE_KEY_PAIR;
    public const ASYMMETRIC_SIGNATURE_PUBLIC_KEY = KeyTypeConstants::ASYMMETRIC_SIGNATURE_PUBLIC_KEY;
    public const ASYMMETRIC_SIGNATURE_SECRET_KEY = KeyTypeConstants::ASYMMETRIC_SIGNATURE_SECRET_KEY;
    public const SYMMETRIC_AUTHENTICATION_KEY = KeyTypeConstants::SYMMETRIC_AUTHENTICATION_KEY;
    public const SYMMETRIC_ENCRYPTION_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_KEY;
    public const SYMMETRIC_ENCRYPTION_PUBLIC_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_PUBLIC_KEY;
    public const SYMMETRIC_ENCRYPTION_SECRET_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_SECRET_KEY;
    public const SYMMETRIC_SIGNATURE_PUBLIC_KEY = KeyTypeConstants::SYMMETRIC_SIGNATURE_PUBLIC_KEY;
    public const SYMMETRIC_SIGNATURE_SECRET_KEY = KeyTypeConstants::SYMMETRIC_SIGNATURE_SECRET_KEY;
    public const UNKNOWN_KEY = KeyTypeConstants::UNKNOWN_KEY;
    public const HEX_KEY = KeyTypeConstants::HEX_KEY;
    public const RAW_KEY = KeyTypeConstants::RAW_KEY;

    public function getAdapter(string $adapter): KeyFactoryAdapterInterface;

    public function generateKey(KeyConfigInterface $config, string $adapter): ?KeyInterface;

    public function buildKeyFromRawKeyData(string $hex, string $type, string $adapter, string $version): KeyInterface;

    public function getRawKeyMaterial(KeyInterface $key): HiddenString;
}
