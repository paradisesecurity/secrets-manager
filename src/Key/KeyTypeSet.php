<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

/**
 * Predefined sets of key types for common use cases.
 * 
 * This provides a centralized place to define logical groupings
 * of key types that are frequently used together.
 */
final class KeyTypeSet
{
    /**
     * Authentication keys only.
     * 
     * @return array<KeyType>
     */
    public static function authentication(): array
    {
        return [
            KeyType::SYMMETRIC_AUTHENTICATION_KEY,
        ];
    }

    /**
     * All symmetric keys.
     * 
     * @return array<KeyType>
     */
    public static function symmetric(): array
    {
        return KeyType::allSymmetric();
    }

    /**
     * All asymmetric keys.
     * 
     * @return array<KeyType>
     */
    public static function asymmetric(): array
    {
        return KeyType::allAsymmetric();
    }

    /**
     * All encryption-related keys (both symmetric and asymmetric).
     * 
     * @return array<KeyType>
     */
    public static function encryption(): array
    {
        return KeyType::allEncryption();
    }

    /**
     * All signature-related keys.
     * 
     * @return array<KeyType>
     */
    public static function signature(): array
    {
        return KeyType::allSignature();
    }

    /**
     * Keys suitable for file encryption.
     * 
     * @return array<KeyType>
     */
    public static function fileEncryption(): array
    {
        return [
            KeyType::SYMMETRIC_ENCRYPTION_KEY,
            KeyType::ASYMMETRIC_ENCRYPTION_KEY_PAIR,
        ];
    }

    /**
     * Keys suitable for message encryption.
     * 
     * @return array<KeyType>
     */
    public static function messageEncryption(): array
    {
        return [
            KeyType::SYMMETRIC_ENCRYPTION_KEY,
            KeyType::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
        ];
    }

    /**
     * Keys suitable for keyring protection.
     * 
     * @return array<KeyType>
     */
    public static function keyringProtection(): array
    {
        return [
            KeyType::SYMMETRIC_ENCRYPTION_KEY,
            KeyType::SYMMETRIC_AUTHENTICATION_KEY,
        ];
    }

    /**
     * All master key types.
     * 
     * @return array<KeyType>
     */
    public static function masterKeys(): array
    {
        return [
            KeyType::SYMMETRIC_ENCRYPTION_KEY,
            KeyType::ASYMMETRIC_SIGNATURE_KEY_PAIR,
            KeyType::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            KeyType::ASYMMETRIC_SIGNATURE_SECRET_KEY,
        ];
    }
}
