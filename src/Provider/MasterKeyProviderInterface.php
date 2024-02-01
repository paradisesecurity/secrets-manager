<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;

interface MasterKeyProviderInterface
{
    public const UNIQUE_ID_LENGTH = 64;

    public const MASTER_SYMMETRIC_ENCRYPTION_KEY = 'master_symmetric_encryption_key';

    public const MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR = 'master_asymmetric_signature_key_pair';

    public const MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY = 'master_asymmetric_signature_secret_key';

    public const MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY = 'master_asymmetric_signature_public_key';

    public function setAccessor(KeyManagerInterface $keyManager, MasterKeyProviderInterface $keyProvider): void;

    public function getKeys(string $accessor): array;

    public function getEncryptionKey(string $accessor): ?KeyInterface;

    public function hasSignatureKeyPair(): bool;

    public function getSignatureKeyPair(string $accessor): ?KeyInterface;

    public function getSignatureSecretKey(string $accessor): ?KeyInterface;

    public function getSignaturePublicKey(string $accessor): ?KeyInterface;
}
