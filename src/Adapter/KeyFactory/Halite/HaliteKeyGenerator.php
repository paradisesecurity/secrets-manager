<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\Halite;

use ParadiseSecurity\Component\SecretsManager\Exception\UnableToGenerateKeyException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParagonIE\Halite\Key as HaliteKey;
use ParagonIE\Halite\KeyFactory as HaliteKeyFactory;
use ParagonIE\Halite\KeyPair as HaliteKeyPair;
use ParagonIE\HiddenString\HiddenString;

use function is_callable;
use function is_int;
use function is_string;

use const SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;

/**
 * Generates new cryptographic keys using Halite.
 */
final class HaliteKeyGenerator
{
    /**
     * Generates a key based on configuration.
     */
    public function generate(string $type, array $config): HaliteKey|HaliteKeyPair
    {
        $methodName = $this->normalizeMethodName('generate_' . $type);

        if (!is_callable([$this, $methodName], true)) {
            throw new UnableToGenerateKeyException(
                "No generation method for key type: {$type}"
            );
        }

        try {
            return $this->$methodName($config);
        } catch (\Exception $exception) {
            throw new UnableToGenerateKeyException(
                "Failed to generate key type '{$type}': {$exception->getMessage()}",
                $exception
            );
        }
    }

    /**
     * Gets default configuration for key generation.
     */
    public function getDefaultConfig(): array
    {
        return [
            KeyConfigInterface::PASSWORD => null,
            KeyConfigInterface::SALT => null,
            KeyConfigInterface::SECURITY_LEVEL => HaliteKeyFactory::INTERACTIVE,
            KeyConfigInterface::ALGORITHM => SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        ];
    }

    /**
     * Validates if configuration is complete for key derivation.
     */
    public function canDeriveKey(array $config): bool
    {
        if (!($config[KeyConfigInterface::PASSWORD] instanceof HiddenString)) {
            return false;
        }
        if (!is_string($config[KeyConfigInterface::SALT])) {
            return false;
        }
        if (!is_string($config[KeyConfigInterface::SECURITY_LEVEL])) {
            return false;
        }
        if (!is_int($config[KeyConfigInterface::ALGORITHM])) {
            return false;
        }
        return true;
    }

    /**
     * Normalizes method name from snake_case to camelCase.
     */
    private function normalizeMethodName(string $name): string
    {
        return lcfirst(str_replace('_', '', ucwords($name, '_')));
    }

    // Generation methods for each key type

    private function generateAsymmetricSignatureKeyPair(array $config): HaliteKeyPair
    {
        if ($this->canDeriveKey($config)) {
            return HaliteKeyFactory::deriveSignatureKeyPair(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }

        return HaliteKeyFactory::generateSignatureKeyPair();
    }

    private function generateAsymmetricEncryptionKeyPair(array $config): HaliteKeyPair
    {
        if ($this->canDeriveKey($config)) {
            return HaliteKeyFactory::deriveEncryptionKeyPair(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }

        return HaliteKeyFactory::generateEncryptionKeyPair();
    }

    private function generateSymmetricEncryptionKey(array $config): HaliteKey
    {
        if ($this->canDeriveKey($config)) {
            return HaliteKeyFactory::deriveEncryptionKey(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }

        return HaliteKeyFactory::generateEncryptionKey();
    }

    private function generateSymmetricAuthenticationKey(array $config): HaliteKey
    {
        if ($this->canDeriveKey($config)) {
            return HaliteKeyFactory::deriveAuthenticationKey(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }

        return HaliteKeyFactory::generateAuthenticationKey();
    }
}
