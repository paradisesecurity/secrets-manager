<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key\Integrity;

use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\FileEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyringIntegrityException;
use ParadiseSecurity\Component\SecretsManager\File\Checksum;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

/**
 * Verifies and generates keyring integrity data (checksums and signatures).
 * Extracts crypto validation logic from KeyManager.
 */
final class KeyringIntegrityVerifier
{
    public function __construct(
        private EncryptionAdapterInterface $encryptionAdapter,
    ) {
    }

    public function generateChecksum(mixed $readOnlyFile): string
    {
        $request = new FileEncryptionRequest($readOnlyFile, null, []);
        
        try {
            return $this->encryptionAdapter->checksum($request);
        } catch (UnableToEncryptMessageException $exception) {
            throw new KeyringIntegrityException(
                "Failed to generate checksum: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Generates a cryptographic signature for the keyring file.
     *
     * @param resource $readOnlyFile The file stream to sign
     * @param KeyInterface $secretKey The secret key for signing
     * @return string The generated signature
     * @throws KeyringIntegrityException If signature generation fails
     */
    public function generateSignature(mixed $readOnlyFile, KeyInterface $secretKey): string
    {
        $config = [EncryptionRequestInterface::ASYMMETRIC => true];
        $request = new FileEncryptionRequest($readOnlyFile, null, $secretKey, $config);
        
        try {
            return $this->encryptionAdapter->sign($request);
        } catch (UnableToEncryptMessageException $exception) {
            throw new KeyringIntegrityException(
                "Failed to generate signature: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    public function verifyChecksum(string $calculatedChecksum, Checksum $storedChecksum): bool
    {
        return hash_equals($storedChecksum->getChecksum(), $calculatedChecksum);
    }

    public function verifySignature(
        mixed $readOnlyFile,
        Checksum $storedChecksum,
        KeyInterface $publicKey
    ): bool {
        $config = [
            EncryptionRequestInterface::ASYMMETRIC => true,
            EncryptionRequestInterface::SIGNATURE => $storedChecksum->getSignature(),
        ];
        $request = new FileEncryptionRequest($readOnlyFile, null, [$publicKey], $config);
        
        try {
            return $this->encryptionAdapter->verify($request);
        } catch (\Exception $exception) {
            throw new KeyringIntegrityException(
                "Signature verification failed: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Formats checksum and signature into the checksum file format.
     *
     * @param string $checksum The checksum hash
     * @param string $signature The cryptographic signature
     * @return string The formatted checksum file content
     */
    public function createChecksumFile(string $checksum, string $signature): string
    {
        return $checksum . $signature;
    }

    public function parseChecksumFile(string $checksumFileContents): Checksum
    {
        return new Checksum($checksumFileContents);
    }
}
