<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key\Integrity;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\Builder\EncryptionRequestBuilder;
use ParadiseSecurity\Component\SecretsManager\Exception\InvalidEncryptionRequestException;
use ParadiseSecurity\Component\SecretsManager\Exception\InvalidSignatureOrChecksumException;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyringIntegrityException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\File\Checksum;
use ParadiseSecurity\Component\SecretsManager\File\ChecksumInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

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

    /**
     * Generates checksum for a file.
     * 
     * @param mixed $readOnlyFile File path or resource
     * @return string Raw checksum hash (88 bytes, base64-encoded)
     * @throws KeyringIntegrityException If checksum generation fails
     */
    public function generateChecksum(mixed $readOnlyFile): string
    {
        $request = EncryptionRequestBuilder::create()
            ->buildForChecksum($readOnlyFile);

        try {
            return $this->encryptionAdapter->checksum($request);
        } catch (InvalidEncryptionRequestException $exception) {
            // Request validation failed
            throw new KeyringIntegrityException(
                "Invalid checksum request: {$exception->getMessage()}",
                previous: $exception
            );
        } catch (UnableToEncryptMessageException $exception) {
            // Operation failed
            throw new KeyringIntegrityException(
                "Failed to generate checksum: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Generates authenticated checksum with key.
     * 
     * @param mixed $readOnlyFile File path or resource
     * @param KeyInterface $authKey Authentication key
     * @return string Raw checksum hash (88 bytes, base64-encoded)
     * @throws KeyringIntegrityException If checksum generation fails
     */
    public function generateAuthenticatedChecksum(
        mixed $readOnlyFile,
        KeyInterface $authKey
    ): string {
        $request = EncryptionRequestBuilder::create()
            ->withKey($authKey)
            ->buildForChecksum($readOnlyFile);

        try {
            return $this->encryptionAdapter->checksum($request);
        } catch (InvalidEncryptionRequestException $exception) {
            throw new KeyringIntegrityException(
                "Invalid authenticated checksum request: {$exception->getMessage()}",
                previous: $exception
            );
        } catch (UnableToEncryptMessageException $exception) {
            throw new KeyringIntegrityException(
                "Failed to generate authenticated checksum: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Signs a checksum with private key.
     * 
     * @param string $checksum Checksum to sign
     * @param KeyInterface $privateKey Signing key
     * @return string Signature (88 bytes, base64-encoded)
     * @throws KeyringIntegrityException If signing fails
     */
    public function signChecksum(string $checksum, KeyInterface $privateKey): string
    {
        // Implementation depends on encryption adapter
        // This is a placeholder - adapt to your actual signing method
        try {
            $request = EncryptionRequestBuilder::create()
                ->withKey($privateKey)
                ->buildForMessage(new HiddenString($checksum));

            return $this->encryptionAdapter->sign($request);
        } catch (\Exception $exception) {
            throw new KeyringIntegrityException(
                "Failed to sign checksum: {$exception->getMessage()}",
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
        $request = EncryptionRequestBuilder::create()
            ->withKey($secretKey)
            ->asymmetric()
            ->buildForSignature($readOnlyFile);

        try {
            return $this->encryptionAdapter->sign($request);
        } catch (UnableToEncryptMessageException $exception) {
            throw new KeyringIntegrityException(
                "Failed to generate signature: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Verifies calculated checksum matches stored checksum.
     * 
     * Uses constant-time comparison to prevent timing attacks.
     * 
     * @param string $calculatedChecksum Newly calculated checksum
     * @param ChecksumInterface $storedChecksum Stored checksum to compare against
     * @return bool True if checksums match
     */
    public function verifyChecksum(string $calculatedChecksum, ChecksumInterface $storedChecksum): bool
    {
        return hash_equals($storedChecksum->getChecksum(), $calculatedChecksum);
    }

    /**
     * Verifies checksum signature with public key.
     * 
     * @param mixed $readOnlyFile File path or resource
     * @param ChecksumInterface $checksum Checksum with signature
     * @param KeyInterface $publicKey Public verification key
     * @return bool True if signature valid
     * @throws KeyringIntegrityException If verification fails
     */
    public function verifySignature(
        mixed $readOnlyFile,
        ChecksumInterface $storedChecksum,
        KeyInterface $publicKey
    ): bool {
        $request = EncryptionRequestBuilder::create()
            ->withKey($publicKey)
            ->withSignature($storedChecksum->getSignature())
            ->asymmetric()
            ->buildForVerification($readOnlyFile);
        
        try {
            return $this->encryptionAdapter->verify($request);
        } catch (\Exception $exception) {
            throw new KeyringIntegrityException(
                "Failed to verify signature: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Performs complete integrity check: checksum and signature.
     * 
     * @param mixed $file File to verify
     * @param ChecksumInterface $storedChecksum Stored checksum with signature
     * @param KeyInterface|null $publicKey Optional public key for signature verification
     * @return bool True if integrity verified
     * @throws KeyringIntegrityException If verification fails
     */
    public function verifyIntegrity(
        mixed $file,
        ChecksumInterface $storedChecksum,
        ?KeyInterface $publicKey = null
    ): bool {
        // Verify checksum
        $calculatedChecksum = $this->generateChecksum($file);
        
        if (!$this->verifyChecksum($calculatedChecksum, $storedChecksum)) {
            throw new KeyringIntegrityException(
                'Checksum verification failed. File may have been modified.'
            );
        }

        // Verify signature if key provided
        if ($publicKey !== null) {
            if (!$this->verifySignature($file, $storedChecksum, $publicKey)) {
                throw new KeyringIntegrityException(
                    'Signature verification failed. Checksum may have been tampered with.'
                );
            }
        }

        return true;
    }

    /**
     * Creates a Checksum value object from checksum and signature.
     * 
     * @param string $checksumHash Checksum hash
     * @param string $signature Cryptographic signature
     * @return ChecksumInterface Checksum value object
     * @throws KeyringIntegrityException If checksum creation fails
     */
    public function createChecksum(string $checksumHash, string $signature): ChecksumInterface
    {
        try {
            return Checksum::fromParts($checksumHash, $signature);
        } catch (InvalidSignatureOrChecksumException $exception) {
            throw new KeyringIntegrityException(
                "Failed to create checksum: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Creates checksum file contents from checksum and signature.
     * 
     * @param string $checksumHash Checksum hash
     * @param string $signature Cryptographic signature
     * @return string Checksum file contents (176 bytes)
     * @throws KeyringIntegrityException If creation fails
     */
    public function createChecksumFile(string $checksumHash, string $signature): string
    {
        $checksum = $this->createChecksum($checksumHash, $signature);
        return $checksum->toString();
    }

    /**
     * Parses checksum file contents into Checksum value object.
     * 
     * @param string $checksumFileContents Combined checksum and signature (176 bytes)
     * @return ChecksumInterface Parsed checksum
     * @throws KeyringIntegrityException If parsing fails
     */
    public function parseChecksumFile(string $checksumFileContents): ChecksumInterface
    {
        try {
            return Checksum::fromString($checksumFileContents);
        } catch (InvalidSignatureOrChecksumException $exception) {
            throw new KeyringIntegrityException(
                "Failed to parse checksum file: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }
}
