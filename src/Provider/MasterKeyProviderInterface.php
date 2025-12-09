<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

interface MasterKeyProviderInterface
{
    public const UNIQUE_ID_LENGTH = 64;

    public const MASTER_SYMMETRIC_ENCRYPTION_KEY = 'master_symmetric_encryption_key';

    public const MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR = 'master_asymmetric_signature_key_pair';

    public const MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY = 'master_asymmetric_signature_secret_key';

    public const MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY = 'master_asymmetric_signature_public_key';

    public function getKeys(): array;

    public function getEncryptionKey(): KeyInterface;

    public function hasSignatureKeyPair(): bool;

    public function getSignatureKeyPair(): KeyInterface;

    public function getSignatureSecretKey(): KeyInterface;

    public function getSignaturePublicKey(): KeyInterface;
}
