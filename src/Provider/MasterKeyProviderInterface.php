<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Exception\MasterKeyException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

/**
 * Interface for master key provider.
 * 
 * Master keys are the root of trust in the secrets management system.
 * They are used to:
 * - Encrypt/decrypt data encryption keys (DEKs)
 * - Sign and verify keyring checksums
 * - Bootstrap the entire encryption hierarchy
 * 
 * Security considerations:
 * - Master keys must be loaded securely on application bootstrap
 * - Access to master keys should be logged and audited
 * - Master keys should be rotated periodically
 * - Lost master keys require system-wide rekeying
 * 
 * Key types required:
 * 1. Symmetric Encryption Key: Encrypts data encryption keys
 * 2. Signature Keys: Signs keyring checksums for integrity
 *    - Either a key pair OR separate public/secret keys
 * 
 * @see https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-130.pdf
 */
interface MasterKeyProviderInterface
{
    /** Length of unique identifiers in bytes */
    public const UNIQUE_ID_LENGTH = 64;

    /** Master key names */
    public const MASTER_SYMMETRIC_ENCRYPTION_KEY = 'master_symmetric_encryption_key';
    public const MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR = 'master_asymmetric_signature_key_pair';
    public const MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY = 'master_asymmetric_signature_secret_key';
    public const MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY = 'master_asymmetric_signature_public_key';

    /**
     * Gets all master keys.
     * 
     * Returns encryption key and signature keys (either pair or separate).
     * 
     * @return array<KeyInterface> Master keys
     */
    public function getKeys(): array;

    /**
     * Gets the master encryption key.
     * 
     * This key is used to encrypt data encryption keys (envelope encryption).
     * 
     * @return KeyInterface Master encryption key
     */
    public function getEncryptionKey(): KeyInterface;

    /**
     * Checks if signature keys are provided as a key pair.
     * 
     * @return bool True if signature key pair exists
     */
    public function hasSignatureKeyPair(): bool;

    /**
     * Gets the signature key pair.
     * 
     * @return KeyInterface Signature key pair
     * @throws MasterKeyException If key pair not available
     */
    public function getSignatureKeyPair(): KeyInterface;

    /**
     * Gets the signature secret key.
     * 
     * Used for signing operations.
     * 
     * @return KeyInterface Signature secret key
     * @throws MasterKeyException If secret key not available
     */
    public function getSignatureSecretKey(): KeyInterface;

    /**
     * Gets the signature public key.
     * 
     * Used for verification operations.
     * 
     * @return KeyInterface Signature public key
     * @throws MasterKeyException If public key not available
     */
    public function getSignaturePublicKey(): KeyInterface;

    /**
     * Checks if all required master keys are loaded.
     * 
     * @return bool True if all keys present
     */
    public function isComplete(): bool;

    /**
     * Gets list of missing required keys.
     * 
     * @return array<string> Names of missing keys
     */
    public function getMissingKeys(): array;
}
