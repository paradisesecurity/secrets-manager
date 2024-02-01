<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Factory;

use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\Key as HaliteKey;
use ParagonIE\Halite\KeyFactory as HaliteKeyFactory;
use ParagonIE\Halite\KeyPair as HaliteKeyPair;
use ParagonIE\HiddenString\HiddenString;

use function is_callable;
use function is_int;
use function is_null;
use function is_string;

final class HaliteKeyFactoryAdapter extends AbstractKeyFactoryAdapter implements KeyFactoryAdapterInterface
{
    public const ADAPTER_NAME = 'halite';

    public const CURRENT_VERSION = Halite::VERSION;

    public const HALITE_KEY = 'halite_key';

    public const SUPPORTED_KEY_TYPES = [self::HALITE_KEY, KeyFactoryInterface::HEX_KEY, KeyFactoryInterface::RAW_KEY];

    public function __construct(
        string $version = self::CURRENT_VERSION
    ) {
        $this->name = self::ADAPTER_NAME;
        $this->supported = self::SUPPORTED_KEY_TYPES;
        $this->version = $version;

        parent::__construct();
    }

    public function getAdapterSpecificKeyType(KeyInterface $key): string
    {
        return self::HALITE_KEY;
    }

    public function getAdapterRequiredKey(
        KeyInterface $key,
        string $type
    ): mixed {
        $methodName = 'get_' . $type;
        $method = $this->convertSnakeCaseToCamelCase($methodName);

        if (!is_callable([$this, $method], true)) {
            $this->unableToLoadKeyType($type);
        }

        try {
            return $this->$method($key);
        } catch (\Exception $exception) {
            $this->unableToLoadKeyType($type);
        }
    }

    private function getRawKey(KeyInterface $key): HiddenString
    {
        return new HiddenString(
            HaliteKeyFactory::getKeyDataFromString(
                Hex::decode($this->getHexKey($key)->getString())
            )
        );
    }

    private function getHaliteKey(KeyInterface $key): HaliteKey|HaliteKeyPair
    {
        $type = $key->getType();
        $methodName = 'import_' . $type;
        $method = $this->convertSnakeCaseToCamelCase($methodName);

        if (!is_callable([$this, $method], true)) {
            $this->unableToLoadKeyType($type);
        }

        try {
            return $this->$method($this->getHexKey($key));
        } catch (\Exception $exception) {
            $this->unableToLoadKeyType($type);
        }

        $this->unableToLoadKeyType($type);
    }

    public function splitKeyPair(KeyInterface $key, string $keyType): array
    {
        $keys = [];
        $keyPair = $this->getAdapterRequiredKey($key, $keyType);
        $secret = $keyPair->getSecretKey();
        $public = $keyPair->getPublicKey();

        $type = $key->getType();
        $version = $key->getVersion();

        $children = $this->getChildKeys($type);
        foreach ($children as $child) {
            if ($this->isPublicKey($child)) {
                $publicType = \str_replace('key_pair', 'public_key', $type);
                $keys[] = $this->createNewKeyFromHaliteKey($public, $publicType, $version);
            }
            if ($this->isSecretKey($child)) {
                $secretType = \str_replace('key_pair', 'secret_key', $type);
                $keys[] = $this->createNewKeyFromHaliteKey($secret, $secretType, $version);
            }
        }

        return $keys;
    }

    private function importAsymmetricSignatureKeyPair(
        HiddenString $keyData
    ): HaliteKeyPair {
        return HaliteKeyFactory::importSignatureKeyPair($keyData);
    }

    private function importAsymmetricEncryptionKeyPair(
        HiddenString $keyData
    ): HaliteKeyPair {
        return HaliteKeyFactory::importEncryptionKeyPair($keyData);
    }

    private function importAsymmetricSignatureSecretKey(
        HiddenString $keyData
    ): HaliteKey {
        return $this->importSymmetricSignatureSecretKey($keyData);
    }

    private function importAsymmetricSignaturePublicKey(
        HiddenString $keyData
    ): HaliteKey {
        return $this->importSymmetricSignaturePublicKey($keyData);
    }

    private function importAsymmetricEncryptionSecretKey(
        HiddenString $keyData
    ): HaliteKey {
        return $this->importSymmetricEncryptionSecretKey($keyData);
    }

    private function importAsymmetricEncryptionPublicKey(
        HiddenString $keyData
    ): HaliteKey {
        return $this->importSymmetricEncryptionPublicKey($keyData);
    }

    private function importSymmetricSignatureSecretKey(
        HiddenString $keyData
    ): HaliteKey {
        return HaliteKeyFactory::importSignatureSecretKey($keyData);
    }

    private function importSymmetricSignaturePublicKey(
        HiddenString $keyData
    ): HaliteKey {
        return HaliteKeyFactory::importSignaturePublicKey($keyData);
    }

    private function importSymmetricEncryptionSecretKey(
        HiddenString $keyData
    ): HaliteKey {
        return HaliteKeyFactory::importEncryptionSecretKey($keyData);
    }

    private function importSymmetricEncryptionPublicKey(
        HiddenString $keyData
    ): HaliteKey {
        return HaliteKeyFactory::importEncryptionPublicKey($keyData);
    }

    private function importSymmetricEncryptionKey(
        HiddenString $keyData
    ): HaliteKey {
        return HaliteKeyFactory::importEncryptionKey($keyData);
    }

    private function importSymmetricAuthenticationKey(
        HiddenString $keyData
    ): HaliteKey {
        return HaliteKeyFactory::importAuthenticationKey($keyData);
    }

    public function getDefaultConfig(string $version = null): array
    {
        if (is_null($version)) {
            $version = $this->getVersion();
        }
        return $this->getVersionedConfig($version);
    }

    public function generateKey(KeyConfigInterface $config): KeyInterface
    {
        $type = $config->getType();
        $methodName = 'generate_' . $type;
        $method = $this->convertSnakeCaseToCamelCase($methodName);

        if (!is_callable([$this, $method], true)) {
            $this->unableToGenerateKeyType($type);
        }

        try {
            $processedConfig = $this->processConfig($config);
            $key = $this->$method($processedConfig);
            $version = $config->getVersion();
            return $this->createNewKeyFromHaliteKey($key, $type, $version);
        } catch (\Exception $exception) {
            $this->unableToGenerateKeyType($type);
        }
    }

    private function createNewKeyFromHaliteKey(
        HaliteKey|HaliteKeyPair $key,
        string $type,
        string $version,
    ): KeyInterface {
        $hex = $this->getHexFromHaliteKey($key);
        $name = $this->getName();
        return new Key($hex, $type, $name, $version);
    }

    private function getHexFromHaliteKey(
        HaliteKey|HaliteKeyPair $key
    ): HiddenString {
        return HaliteKeyFactory::export($key);
    }

    private function generateAsymmetricSignatureKeyPair(
        array $config
    ): HaliteKeyPair {
        if ($this->verifyGenerateKeyConfig($config)) {
            return HaliteKeyFactory::deriveSignatureKeyPair(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }
        return HaliteKeyFactory::generateSignatureKeyPair();
    }

    private function generateAsymmetricEncryptionKeyPair(
        array $config
    ): HaliteKeyPair {
        if ($this->verifyGenerateKeyConfig($config)) {
            return HaliteKeyFactory::deriveEncryptionKeyPair(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }
        return HaliteKeyFactory::generateEncryptionKeyPair();
    }

    private function generateSymmetricEncryptionKey(
        array $config
    ): HaliteKey {
        if ($this->verifyGenerateKeyConfig($config)) {
            return HaliteKeyFactory::deriveEncryptionKey(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }
        return HaliteKeyFactory::generateEncryptionKey();
    }

    private function generateSymmetricAuthenticationKey(
        array $config
    ): HaliteKey {
        if ($this->verifyGenerateKeyConfig($config)) {
            return HaliteKeyFactory::deriveAuthenticationKey(
                $config[KeyConfigInterface::PASSWORD],
                $config[KeyConfigInterface::SALT],
                $config[KeyConfigInterface::SECURITY_LEVEL],
                $config[KeyConfigInterface::ALGORITHM],
            );
        }
        return HaliteKeyFactory::generateAuthenticationKey();
    }

    private function verifyGenerateKeyConfig(array $config): bool
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

    private function processConfig(KeyConfigInterface $config): array
    {
        $version = $config->getVersion();
        if (is_null($version)) {
            $version = $this->getVersion();
            $config->setVersion($version);
        }
        $defaultConfig = $this->getVersionedConfig($version);
        $newConfig = $config->getConfiguration();
        return $this->replaceDefaultConfigValues($defaultConfig, $newConfig);
    }

    private function getVersionedConfig(string $version): array
    {
        return [
            KeyConfigInterface::PASSWORD => null,
            KeyConfigInterface::SALT => null,
            KeyConfigInterface::SECURITY_LEVEL => HaliteKeyFactory::INTERACTIVE,
            KeyConfigInterface::ALGORITHM => SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        ];
    }
}
