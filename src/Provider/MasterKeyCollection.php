<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Exception\MasterKeyException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

/**
 * Value object representing a collection of master keys.
 * 
 * Validates that required keys are present and of correct types.
 */
final class MasterKeyCollection
{
    private ?KeyInterface $encryptionKey = null;
    private ?KeyInterface $signatureKeyPair = null;
    private ?KeyInterface $signatureSecretKey = null;
    private ?KeyInterface $signaturePublicKey = null;

    /**
     * Adds a key to the collection.
     * 
     * @param KeyInterface $key Key to add
     * @throws MasterKeyException If key type is invalid
     */
    public function addKey(KeyInterface $key): void
    {
        $type = $key->getType();

        match ($type) {
            KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY => $this->encryptionKey = $key,
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR => $this->signatureKeyPair = $key,
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY => $this->signatureSecretKey = $key,
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY => $this->signaturePublicKey = $key,
            default => throw MasterKeyException::invalidKeyType($type),
        };
    }

    /**
     * Validates that all required keys are present.
     * 
     * @throws MasterKeyException If required keys missing
     */
    public function validate(): void
    {
        if ($this->encryptionKey === null) {
            throw MasterKeyException::missingKey(
                MasterKeyProviderInterface::MASTER_SYMMETRIC_ENCRYPTION_KEY
            );
        }

        if (!$this->hasSignatureKeys()) {
            throw MasterKeyException::missingSignatureKeys();
        }
    }

    /**
     * Checks if signature keys are available.
     */
    public function hasSignatureKeys(): bool
    {
        return $this->signatureKeyPair !== null
            || ($this->signaturePublicKey !== null && $this->signatureSecretKey !== null);
    }

    /**
     * Checks if signature key pair is available.
     */
    public function hasSignatureKeyPair(): bool
    {
        return $this->signatureKeyPair !== null;
    }

    /**
     * Gets encryption key.
     * 
     * @throws MasterKeyException If not set
     */
    public function getEncryptionKey(): KeyInterface
    {
        if ($this->encryptionKey === null) {
            throw MasterKeyException::missingKey(
                MasterKeyProviderInterface::MASTER_SYMMETRIC_ENCRYPTION_KEY
            );
        }

        return $this->encryptionKey;
    }

    /**
     * Gets signature key pair.
     * 
     * @throws MasterKeyException If not set
     */
    public function getSignatureKeyPair(): KeyInterface
    {
        if ($this->signatureKeyPair === null) {
            throw MasterKeyException::missingKey(
                MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR
            );
        }

        return $this->signatureKeyPair;
    }

    /**
     * Gets signature secret key.
     * 
     * @throws MasterKeyException If not set
     */
    public function getSignatureSecretKey(): KeyInterface
    {
        if ($this->signatureSecretKey === null) {
            throw MasterKeyException::missingKey(
                MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY
            );
        }

        return $this->signatureSecretKey;
    }

    /**
     * Gets signature public key.
     * 
     * @throws MasterKeyException If not set
     */
    public function getSignaturePublicKey(): KeyInterface
    {
        if ($this->signaturePublicKey === null) {
            throw MasterKeyException::missingKey(
                MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY
            );
        }

        return $this->signaturePublicKey;
    }

    /**
     * Gets all keys as array.
     * 
     * @return array<KeyInterface> All keys
     */
    public function toArray(): array
    {
        $keys = [];

        if ($this->encryptionKey !== null) {
            $keys[] = $this->encryptionKey;
        }

        if ($this->signatureKeyPair !== null) {
            $keys[] = $this->signatureKeyPair;
            return $keys;
        }

        if ($this->signatureSecretKey !== null) {
            $keys[] = $this->signatureSecretKey;
        }

        if ($this->signaturePublicKey !== null) {
            $keys[] = $this->signaturePublicKey;
        }

        return $keys;
    }

    /**
     * Gets missing required keys.
     * 
     * @return array<string> Names of missing keys
     */
    public function getMissingKeys(): array
    {
        $missing = [];

        if ($this->encryptionKey === null) {
            $missing[] = MasterKeyProviderInterface::MASTER_SYMMETRIC_ENCRYPTION_KEY;
        }

        if (!$this->hasSignatureKeys()) {
            if ($this->signatureKeyPair === null) {
                $missing[] = MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR;
            }
            if ($this->signatureSecretKey === null) {
                $missing[] = MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY;
            }
            if ($this->signaturePublicKey === null) {
                $missing[] = MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY;
            }
        }

        return $missing;
    }
}
