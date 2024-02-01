<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Factory;

use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

interface KeyFactoryInterface
{
    public const ASYMMETRIC_ENCRYPTION_KEY_PAIR = 'asymmetric_encryption_key_pair';

    public const ASYMMETRIC_ENCRYPTION_PUBLIC_KEY = 'asymmetric_encryption_public_key';

    public const ASYMMETRIC_ENCRYPTION_SECRET_KEY = 'asymmetric_encryption_secret_key';

    public const ASYMMETRIC_SIGNATURE_KEY_PAIR = 'asymmetric_signature_key_pair';

    public const ASYMMETRIC_SIGNATURE_PUBLIC_KEY = 'asymmetric_signature_public_key';

    public const ASYMMETRIC_SIGNATURE_SECRET_KEY = 'asymmetric_signature_secret_key';

    public const SYMMETRIC_AUTHENTICATION_KEY = 'symmetric_authentication_key';

    public const SYMMETRIC_ENCRYPTION_KEY = 'symmetric_encryption_key';

    public const SYMMETRIC_ENCRYPTION_PUBLIC_KEY = 'symmetric_encryption_public_key';

    public const SYMMETRIC_ENCRYPTION_SECRET_KEY = 'symmetric_encryption_secret_key';

    public const SYMMETRIC_SIGNATURE_PUBLIC_KEY = 'symmetric_signature_public_key';

    public const SYMMETRIC_SIGNATURE_SECRET_KEY = 'symmetric_signature_secret_key';

    public const UNKNOWN_KEY = 'unknown_key';

    public const HEX_KEY = 'hex_key';

    public const RAW_KEY = 'raw_key';

    public function getAdapter(string $adapter): KeyFactoryAdapterInterface;

    public function generateKey(KeyConfigInterface $config, string $adapter): ?KeyInterface;

    public function buildKeyFromRawKeyData(string $hex, string $type, string $adapter, string $version): KeyInterface;

    public function getRawKeyMaterial(KeyInterface $key): HiddenString;
}
