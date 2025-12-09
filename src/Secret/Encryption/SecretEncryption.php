<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret\Encryption;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretEncryptionException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;

/**
 * Handles envelope encryption for secret values.
 * Implements the envelope encryption pattern with DEK + KMS key.
 */
final class SecretEncryption
{
    public function __construct(
        private EncryptionAdapterInterface $encryptionAdapter,
    ) {
    }

    /**
     * Encrypts a value with a data encryption key (DEK).
     */
    public function encryptValue(KeyInterface $dataKey, string $value): string
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($value),
            $dataKey
        );

        try {
            return $this->encryptionAdapter->encrypt($request);
        } catch (\Exception $exception) {
            throw new SecretEncryptionException(
                "Failed to encrypt secret value: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Decrypts an encrypted value using a data encryption key (DEK).
     */
    public function decryptValue(string $encryptedValue, KeyInterface $dataKey): string
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($encryptedValue),
            $dataKey
        );

        try {
            return $this->encryptionAdapter->decrypt($request)->getString();
        } catch (\Exception $exception) {
            throw new SecretEncryptionException(
                "Failed to decrypt secret value: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Encrypts a data encryption key (DEK) with the KMS key (envelope encryption).
     */
    public function encryptDataKey(KeyInterface $dataKey, KeyInterface $kmsKey): string
    {
        $dataKeyData = [
            'hex' => $dataKey->getHex()->getString(),
            'type' => $dataKey->getType(),
            'version' => $dataKey->getVersion(),
            'adapter' => $dataKey->getAdapter(),
        ];

        try {
            $serializedKey = json_encode(
                $dataKeyData,
                JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR
            );
        } catch (\JsonException $exception) {
            throw new SecretEncryptionException(
                "Failed to serialize data key: {$exception->getMessage()}",
                previous: $exception
            );
        }

        $request = new MessageEncryptionRequest(
            new HiddenString($serializedKey),
            $kmsKey
        );

        try {
            return $this->encryptionAdapter->encrypt($request);
        } catch (\Exception $exception) {
            throw new SecretEncryptionException(
                "Failed to encrypt data key: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Decrypts a data encryption key (DEK) using the KMS key.
     */
    public function decryptDataKey(string $encryptedDataKey, KeyInterface $kmsKey): array
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($encryptedDataKey),
            $kmsKey
        );

        try {
            $decryptedJson = $this->encryptionAdapter->decrypt($request)->getString();
            return json_decode($decryptedJson, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $exception) {
            throw new SecretEncryptionException(
                "Failed to decrypt data key: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }
}
