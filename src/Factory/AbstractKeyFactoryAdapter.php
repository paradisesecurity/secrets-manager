<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Factory;

use ParadiseSecurity\Component\SecretsManager\Adapter\AbstractAdapter;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToGenerateKeyException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

use function in_array;
use function str_contains;

abstract class AbstractKeyFactoryAdapter extends AbstractAdapter
{
    public array $supported = [];

    public function __construct()
    {
        parent::__construct();
    }

    public function getSupportedKeyTypes(): array
    {
        return $this->supported;
    }

    public function supports(string $encryption): bool
    {
        return in_array($encryption, $this->supported, true);
    }

    public function getParentKey(string $type): array
    {
        $encryptionKeyPair = $this->getChildKeys(KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR);
        if (in_array($type, $encryptionKeyPair, true)) {
            return [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR];
        }
        $signatureKeyPair = $this->getChildKeys(KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR);
        if (in_array($type, $signatureKeyPair, true)) {
            return [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR];
        }
        return [];
    }

    public function getChildKeys(string $type): array
    {
        if ($type === KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR) {
            return [
                KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
                KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
            ];
        }
        if ($type === KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR) {
            return [
                KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
                KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY,
            ];
        }
        return [];
    }

    protected function getHexKey(KeyInterface $key): HiddenString
    {
        return $key->getHex();
    }

    public function isKeyPair(string $type): bool
    {
        return str_contains($type, 'key_pair');
    }

    public function isPublicKey(string $type): bool
    {
        return str_contains($type, 'public_key');
    }

    public function isSecretKey(string $type): bool
    {
        return str_contains($type, 'secret_key');
    }

    protected function unableToLoadKeyType(string $type): void
    {
        $type = $this->transformSnakeCaseIntoWord($type);
        throw UnableToLoadKeyException::withType($type);
    }

    protected function unableToGenerateKeyType(string $type): void
    {
        $type = $this->transformSnakeCaseIntoWord($type);
        throw UnableToGenerateKeyException::withType($type);
    }
}
