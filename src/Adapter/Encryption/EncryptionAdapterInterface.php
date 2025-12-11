<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption;

use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParagonIE\HiddenString\HiddenString;

/**
 * Interface for encryption adapters.
 * 
 * All encryption adapters must implement this interface to ensure consistent
 * behavior across different encryption libraries. This allows users to create
 * custom adapters for different encryption backends (Sodium, OpenSSL, etc.)
 * while maintaining compatibility with the SecretsManager component.
 * 
 * @see AbstractEncryptionAdapter for a base implementation with common functionality
 */
interface EncryptionAdapterInterface
{
    /**
     * Gets the required encryption key type for this adapter.
     * 
     * This indicates what type of key objects the adapter expects
     * (e.g., 'halite_key', 'sodium_key').
     * 
     * @return string The required key type identifier
     */
    public function getRequiredEncryptionKeyType(): string;

    /**
     * Calculates a cryptographic checksum (hash) of a file.
     * 
     * Used for integrity verification of files before/after operations.
     * Typically implements BLAKE2b or similar secure hash function.
     * 
     * @param EncryptionRequestInterface $request Contains file reference and optional key
     * @return string The calculated checksum
     * @throws UnableToEncryptMessageException If checksum calculation fails
     */
    public function checksum(EncryptionRequestInterface $request): string;

    /**
     * Encrypts data using asymmetric encryption (authenticated encryption).
     * 
     * Encrypts a message or file using the sender's private key and 
     * recipient's public key. The recipient can verify the sender's identity.
     * 
     * @param EncryptionRequestInterface $request Contains message/file and keys
     * @return string|int The encrypted data (string) or bytes written (int for files)
     * @throws UnableToEncryptMessageException If encryption fails
     */
    public function encrypt(EncryptionRequestInterface $request): string|int;

    /**
     * Decrypts data that was encrypted with encrypt().
     * 
     * Decrypts a message or file using the recipient's private key and
     * sender's public key.
     * 
     * @param EncryptionRequestInterface $request Contains encrypted data and keys
     * @return HiddenString|bool The decrypted message or success status for files
     * @throws UnableToEncryptMessageException If decryption fails
     */
    public function decrypt(EncryptionRequestInterface $request): HiddenString|bool;

    /**
     * Seals data using anonymous asymmetric encryption.
     * 
     * Encrypts a message or file using only the recipient's public key.
     * The sender remains anonymous. Only the recipient with the corresponding
     * private key can decrypt.
     * 
     * @param EncryptionRequestInterface $request Contains message/file and public key
     * @return string|int The sealed data (string) or bytes written (int for files)
     * @throws UnableToEncryptMessageException If sealing fails
     */
    public function seal(EncryptionRequestInterface $request): string|int;

    /**
     * Unseals data that was sealed with seal().
     * 
     * Decrypts anonymous encrypted data using the recipient's private key.
     * 
     * @param EncryptionRequestInterface $request Contains sealed data and private key
     * @return HiddenString|bool The unsealed message or success status for files
     * @throws UnableToEncryptMessageException If unsealing fails
     */
    public function unseal(EncryptionRequestInterface $request): HiddenString|bool;

    /**
     * Creates a digital signature for a message or file.
     * 
     * Signs data using a private key, allowing others to verify authenticity
     * and integrity using the corresponding public key.
     * 
     * @param EncryptionRequestInterface $request Contains message/file and private key
     * @return string The digital signature
     * @throws UnableToEncryptMessageException If signing fails
     */
    public function sign(EncryptionRequestInterface $request): string;

    /**
     * Verifies a digital signature.
     * 
     * Verifies that a signature was created by the holder of the private key
     * corresponding to the provided public key, and that the data hasn't been modified.
     * 
     * For symmetric verification, verifies a MAC (Message Authentication Code).
     * 
     * @param EncryptionRequestInterface $request Contains message/file, signature/MAC, and public/symmetric key
     * @return bool True if signature is valid, false otherwise
     * @throws UnableToEncryptMessageException If verification operation fails
     */
    public function verify(EncryptionRequestInterface $request): bool;

    /**
     * Signs a message and then encrypts it.
     * 
     * Combines sign() and encrypt() operations: signs the message with the
     * sender's private key, then encrypts with the recipient's public key.
     * Provides both authentication and confidentiality.
     * 
     * @param EncryptionRequestInterface $request Contains message, sender's private key, and recipient's public key
     * @return string The signed and encrypted message
     * @throws UnableToEncryptMessageException If operation fails
     */
    public function signAndEncrypt(EncryptionRequestInterface $request): string;

    /**
     * Decrypts a message and then verifies its signature.
     * 
     * Reverse of signAndEncrypt(): decrypts using the recipient's private key,
     * then verifies signature using sender's public key.
     * 
     * @param EncryptionRequestInterface $request Contains encrypted message, recipient's private key, and sender's public key
     * @return HiddenString The decrypted and verified message
     * @throws UnableToEncryptMessageException If decryption or verification fails
     */
    public function verifyAndDecrypt(EncryptionRequestInterface $request): HiddenString;

    /**
     * Generates a Message Authentication Code (MAC) for symmetric authentication.
     * 
     * Creates a MAC that can be used to verify data integrity and authenticity
     * using a shared secret key. Unlike signatures, MACs are symmetric.
     * 
     * @param EncryptionRequestInterface $request Contains message and symmetric authentication key
     * @return string The generated MAC
     * @throws UnableToEncryptMessageException If MAC generation fails
     */
    public function authenticate(EncryptionRequestInterface $request): string;
}
