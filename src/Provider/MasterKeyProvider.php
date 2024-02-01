<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Exception\MissingEncryptionKeyException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Loader\DelegatingKeyLoaderInterface;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;

use function is_null;

final class MasterKeyProvider implements MasterKeyProviderInterface
{
    private string $accessor;

    private KeyInterface $encryptionKey;

    private KeyInterface $signatureKeyPair;

    private KeyInterface $signatureSecretKey;

    private KeyInterface $signaturePublicKey;

    private array $default = [
        MasterKeyProviderInterface::MASTER_SYMMETRIC_ENCRYPTION_KEY,
        MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR,
        MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY,
        MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
    ];

    public function __construct(
        private DelegatingKeyLoaderInterface $delegatingKeyLoader,
        private string $loader
    ) {
        $this->loadMasterKeys();
        $this->accessor = Utility::createUniqueId(MasterKeyProviderInterface::UNIQUE_ID_LENGTH);
    }

    public function setAccessor(
        KeyManagerInterface $keyManager,
        MasterKeyProviderInterface $keyProvider
    ): void {
        if ($keyProvider === $this) {
            $keyManager->setAccessor($this, $keyManager, $this->accessor);
        }
    }

    public function getKeys(string $accessor): array
    {
        $keys = [];
        if ($accessor !== $this->accessor) {
            return $keys;
        }

        $keys[] = $this->encryptionKey;

        if ($this->hasSignatureKeyPair()) {
            $keys[] = $this->signatureKeyPair;
            return $keys;
        }

        $keys[] = $this->signatureSecretKey;
        $keys[] = $this->signaturePublicKey;

        return $keys;
    }

    public function getEncryptionKey(string $accessor): ?KeyInterface
    {
        if ($accessor === $this->accessor) {
            return $this->encryptionKey;
        }

        return null;
    }

    public function hasSignatureKeyPair(): bool
    {
        return isset($this->signatureKeyPair);
    }

    public function getSignatureKeyPair(string $accessor): ?KeyInterface
    {
        if ($accessor === $this->accessor) {
            return $this->signatureKeyPair;
        }

        return null;
    }

    public function getSignatureSecretKey(string $accessor): ?KeyInterface
    {
        if ($accessor === $this->accessor) {
            return $this->signatureSecretKey;
        }

        return null;
    }

    public function getSignaturePublicKey(string $accessor): ?KeyInterface
    {
        if ($accessor === $this->accessor) {
            return $this->signaturePublicKey;
        }

        return null;
    }

    private function loadMasterKeys(): void
    {
        $loader = $this->delegatingKeyLoader->getLoader($this->loader);
        $keys = [];
        foreach ($this->default as $name) {
            $contents = $loader->import($name);
            if (is_null($contents)) {
                $contents = $name;
            }
            try {
                $key = $loader->resolve($contents);
                $keys[] = $key;
            } catch (UnableToLoadKeyException $exception) {
                continue;
            }
        }
        $this->insertMasterKeys($keys);
    }

    private function insertMasterKeys(array $keys): void
    {
        foreach ($keys as $key) {
            $type = $key->getType();
            switch ($type) {
                case KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY:
                    $this->encryptionKey = $key;
                    break;
                case KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR:
                    $this->signatureKeyPair = $key;
                    break;
                case KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY:
                    $this->signatureSecretKey = $key;
                    break;
                case KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY:
                    $this->signaturePublicKey = $key;
                    break;
                default:
                    // Wrong key type provided.
                    break;
            }
        }

        if (!isset($this->encryptionKey)) {
            $this->missingEncryptionKeyType(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        }

        if (!$this->isSignatureKeyProvided()) {
            $this->missingEncryptionKeyType(KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR);
        }
    }

    private function isSignatureKeyProvided(): bool
    {
        if (isset($this->signatureKeyPair)) {
            return true;
        }

        if (isset($this->signaturePublicKey) && isset($this->signatureSecretKey)) {
            return true;
        }

        return false;
    }

    private function missingEncryptionKeyType(string $keyType): void
    {
        throw MissingEncryptionKeyException::withType($keyType);
    }
}
