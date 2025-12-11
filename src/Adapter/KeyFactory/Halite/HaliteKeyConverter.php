<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\Halite;

use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Halite\Key as HaliteKey;
use ParagonIE\Halite\KeyFactory as HaliteKeyFactory;
use ParagonIE\Halite\KeyPair as HaliteKeyPair;
use ParagonIE\HiddenString\HiddenString;

use function is_callable;

/**
 * Converts keys between generic format and Halite-specific format.
 */
final class HaliteKeyConverter
{
    /**
     * Converts generic KeyInterface to Halite key.
     */
    public function toHaliteKey(KeyInterface $key): HaliteKey|HaliteKeyPair
    {
        $type = $key->getType();
        $methodName = $this->normalizeMethodName('import_' . $type);

        if (!is_callable([$this, $methodName], true)) {
            throw new UnableToLoadKeyException(
                "No import method for key type: {$type}"
            );
        }

        try {
            return $this->$methodName($this->getHexKey($key));
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException(
                "Failed to import key type '{$type}': {$exception->getMessage()}",
                $exception
            );
        }
    }

    /**
     * Exports Halite key to HiddenString hex format.
     */
    public function fromHaliteKey(HaliteKey|HaliteKeyPair $key): HiddenString
    {
        return HaliteKeyFactory::export($key);
    }

    /**
     * Converts key to raw binary format.
     */
    public function toRawKey(KeyInterface $key): HiddenString
    {
        return new HiddenString(
            HaliteKeyFactory::getKeyDataFromString(
                Hex::decode($this->getHexKey($key)->getString())
            )
        );
    }

    /**
     * Gets hex representation from key.
     */
    private function getHexKey(KeyInterface $key): HiddenString
    {
        return $key->getHex();
    }

    /**
     * Normalizes method name from snake_case to camelCase.
     */
    private function normalizeMethodName(string $name): string
    {
        return lcfirst(str_replace('_', '', ucwords($name, '_')));
    }

    // Import methods for each key type

    private function importAsymmetricSignatureKeyPair(HiddenString $keyData): HaliteKeyPair
    {
        return HaliteKeyFactory::importSignatureKeyPair($keyData);
    }

    private function importAsymmetricEncryptionKeyPair(HiddenString $keyData): HaliteKeyPair
    {
        return HaliteKeyFactory::importEncryptionKeyPair($keyData);
    }

    private function importAsymmetricSignatureSecretKey(HiddenString $keyData): HaliteKey
    {
        return HaliteKeyFactory::importSignatureSecretKey($keyData);
    }

    private function importAsymmetricSignaturePublicKey(HiddenString $keyData): HaliteKey
    {
        return HaliteKeyFactory::importSignaturePublicKey($keyData);
    }

    private function importAsymmetricEncryptionSecretKey(HiddenString $keyData): HaliteKey
    {
        return HaliteKeyFactory::importEncryptionSecretKey($keyData);
    }

    private function importAsymmetricEncryptionPublicKey(HiddenString $keyData): HaliteKey
    {
        return HaliteKeyFactory::importEncryptionPublicKey($keyData);
    }

    private function importSymmetricEncryptionKey(HiddenString $keyData): HaliteKey
    {
        return HaliteKeyFactory::importEncryptionKey($keyData);
    }

    private function importSymmetricAuthenticationKey(HiddenString $keyData): HaliteKey
    {
        return HaliteKeyFactory::importAuthenticationKey($keyData);
    }
}
