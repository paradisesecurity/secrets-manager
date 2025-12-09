<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret\Processing;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretProcessingException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;
use ParagonIE\HiddenString\HiddenString;

use function json_decode;
use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;

/**
 * Handles secret value encryption, decryption, authentication and verification.
 * Extracts complexity from SecretManager.
 */
final class SecretDataProcessor
{
    public function __construct(
        private EncryptionAdapterInterface $encryptionAdapter,
        private KeyFactoryInterface $keyFactory,
    ) {
    }

    public function encryptValue(KeyInterface $dataKey, mixed $value): string
    {
        // Convert value to JSON
        try {
            $jsonValue = json_encode($value, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SecretProcessingException(
                "Failed to encode secret value: {$e->getMessage()}",
                previous: $e
            );
        }

        // Encrypt
        $request = new MessageEncryptionRequest(
            new HiddenString($jsonValue),
            $dataKey
        );
        
        try {
            return $this->encryptionAdapter->encrypt($request);
        } catch (\Exception $e) {
            throw new SecretProcessingException(
                "Failed to encrypt secret value: {$e->getMessage()}",
                previous: $e
            );
        }
    }

    public function decryptValue(string $encryptedValue, KeyInterface $dataKey): mixed
    {
        // Decrypt
        $request = new MessageEncryptionRequest(
            new HiddenString($encryptedValue),
            $dataKey
        );
        
        try {
            $decrypted = $this->encryptionAdapter->decrypt($request)->getString();
        } catch (\Exception $e) {
            throw new SecretProcessingException(
                "Failed to decrypt secret value: {$e->getMessage()}",
                previous: $e
            );
        }

        // Parse JSON
        try {
            return json_decode($decrypted, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SecretProcessingException(
                "Failed to decode decrypted secret: {$e->getMessage()}",
                previous: $e
            );
        }
    }

    public function authenticateData(string $value, KeyInterface $authKey): string
    {
        $config = [EncryptionRequestInterface::CHOOSE_ENCODER => true];
        $request = new MessageEncryptionRequest(
            new HiddenString($value),
            $authKey,
            $config
        );
        
        try {
            $mac = $this->encryptionAdapter->authenticate($request);
            return $mac . $value;
        } catch (\Exception $e) {
            throw new SecretProcessingException(
                "Failed to authenticate data: {$e->getMessage()}",
                previous: $e
            );
        }
    }

    public function verifyData(string $authenticatedData, KeyInterface $authKey): string
    {
        $mac = Utility::subString($authenticatedData, 0, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        $data = Utility::subString($authenticatedData, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);

        $config = [
            EncryptionRequestInterface::MAC => $mac,
            EncryptionRequestInterface::CHOOSE_ENCODER => true,
        ];
        $request = new MessageEncryptionRequest(
            new HiddenString($data),
            $authKey,
            $config
        );
        
        if (!$this->encryptionAdapter->verify($request)) {
            throw new SecretProcessingException('Secret data authentication failed');
        }

        return $data;
    }

    public function encryptDataKey(KeyInterface $dataKey, KeyInterface $kmsKey): string
    {
        $keyData = [
            'hex' => $dataKey->getHex()->getString(),
            'type' => $dataKey->getType(),
            'version' => $dataKey->getVersion(),
            'adapter' => $dataKey->getAdapter(),
        ];
        
        try {
            $jsonKey = json_encode($keyData, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SecretProcessingException(
                "Failed to encode data key: {$e->getMessage()}",
                previous: $e
            );
        }

        $request = new MessageEncryptionRequest(
            new HiddenString($jsonKey),
            $kmsKey
        );
        
        try {
            return $this->encryptionAdapter->encrypt($request);
        } catch (\Exception $e) {
            throw new SecretProcessingException(
                "Failed to encrypt data key: {$e->getMessage()}",
                previous: $e
            );
        }
    }

    public function decryptDataKey(string $encryptedDataKey, KeyInterface $kmsKey): KeyInterface
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($encryptedDataKey),
            $kmsKey
        );
        
        try {
            $decrypted = $this->encryptionAdapter->decrypt($request)->getString();
            $keyData = json_decode($decrypted, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $e) {
            throw new SecretProcessingException(
                "Failed to decrypt data key: {$e->getMessage()}",
                previous: $e
            );
        }

        return $this->keyFactory->buildKeyFromRawKeyData(
            $keyData['hex'],
            $keyData['type'],
            $keyData['adapter'],
            $keyData['version']
        );
    }
}
