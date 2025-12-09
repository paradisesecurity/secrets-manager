<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key\Encryption;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyringEncryptionException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;
use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionRequestInterface;

/**
 * Handles encryption/decryption of keyring data.
 * Separates crypto operations from KeyManager.
 */
final class KeyringEncryption
{
    public function __construct(
        private EncryptionAdapterInterface $encryptionAdapter,
    ) {
    }

    /**
     * Encrypts serialized keyring data using the master encryption key.
     *
     * @param string $serializedData The JSON string to encrypt
     * @param KeyInterface $encryptionKey The master encryption key
     * @return string The encrypted data
     * @throws KeyringEncryptionException If encryption fails
     */
    public function encrypt(string $serializedData, KeyInterface $encryptionKey): string
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($serializedData),
            $encryptionKey
        );
        
        try {
            return $this->encryptionAdapter->encrypt($request);
        } catch (\Exception $exception) {
            throw new KeyringEncryptionException(
                "Failed to encrypt keyring data: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    public function decrypt(string $ciphertext, KeyInterface $encryptionKey): string
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($ciphertext),
            $encryptionKey
        );
        
        try {
            $decrypted = $this->encryptionAdapter->decrypt($request);
            return $decrypted->getString();
        } catch (\Exception $exception) {
            throw new KeyringEncryptionException(
                "Failed to decrypt keyring data: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    public function verifyMAC(KeyInterface $authKey, string $mac, string $uniqueId): bool
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($uniqueId),
            $authKey,
            [EncryptionRequestInterface::MAC => $mac]
        );

        return $this->encryptionAdapter->verify($request);
    }

    public function generateMAC(KeyInterface $authKey, string $data): string
    {
        $request = new MessageEncryptionRequest(
            new HiddenString($data),
            $authKey
        );
        
        try {
            return $this->encryptionAdapter->authenticate($request);
        } catch (\Exception $exception) {
            throw new KeyringEncryptionException(
                "Failed to generate MAC: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }
}
