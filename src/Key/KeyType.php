<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

/**
 * Enum representing all supported cryptographic key types.
 * 
 * Replaces string-based key type constants from KeyFactoryInterface.
 */
enum KeyType: string
{
    case ASYMMETRIC_ENCRYPTION_KEY_PAIR = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_KEY_PAIR;
    case ASYMMETRIC_ENCRYPTION_PUBLIC_KEY = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY;
    case ASYMMETRIC_ENCRYPTION_SECRET_KEY = KeyTypeConstants::ASYMMETRIC_ENCRYPTION_SECRET_KEY;
    case ASYMMETRIC_SIGNATURE_KEY_PAIR = KeyTypeConstants::ASYMMETRIC_SIGNATURE_KEY_PAIR;
    case ASYMMETRIC_SIGNATURE_PUBLIC_KEY = KeyTypeConstants::ASYMMETRIC_SIGNATURE_PUBLIC_KEY;
    case ASYMMETRIC_SIGNATURE_SECRET_KEY = KeyTypeConstants::ASYMMETRIC_SIGNATURE_SECRET_KEY;
    case SYMMETRIC_AUTHENTICATION_KEY = KeyTypeConstants::SYMMETRIC_AUTHENTICATION_KEY;
    case SYMMETRIC_ENCRYPTION_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_KEY;
    case SYMMETRIC_ENCRYPTION_PUBLIC_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_PUBLIC_KEY;
    case SYMMETRIC_ENCRYPTION_SECRET_KEY = KeyTypeConstants::SYMMETRIC_ENCRYPTION_SECRET_KEY;
    case SYMMETRIC_SIGNATURE_PUBLIC_KEY = KeyTypeConstants::SYMMETRIC_SIGNATURE_PUBLIC_KEY;
    case SYMMETRIC_SIGNATURE_SECRET_KEY = KeyTypeConstants::SYMMETRIC_SIGNATURE_SECRET_KEY;
    case UNKNOWN_KEY = KeyTypeConstants::UNKNOWN_KEY;
    case HEX_KEY = KeyTypeConstants::HEX_KEY;
    case RAW_KEY = KeyTypeConstants::RAW_KEY;

    /**
     * Check if this is a symmetric key type.
     */
    public function isSymmetric(): bool
    {
        return match ($this) {
            self::SYMMETRIC_AUTHENTICATION_KEY,
            self::SYMMETRIC_ENCRYPTION_KEY,
            self::SYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::SYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::SYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::SYMMETRIC_SIGNATURE_SECRET_KEY => true,
            default => false,
        };
    }

    /**
     * Check if this is an asymmetric key type.
     */
    public function isAsymmetric(): bool
    {
        return match ($this) {
            self::ASYMMETRIC_ENCRYPTION_KEY_PAIR,
            self::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::ASYMMETRIC_SIGNATURE_KEY_PAIR,
            self::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::ASYMMETRIC_SIGNATURE_SECRET_KEY => true,
            default => false,
        };
    }

    /**
     * Check if this is a key pair type.
     */
    public function isKeyPair(): bool
    {
        return match ($this) {
            self::ASYMMETRIC_ENCRYPTION_KEY_PAIR,
            self::ASYMMETRIC_SIGNATURE_KEY_PAIR => true,
            default => false,
        };
    }

    /**
     * Check if this is an authentication key.
     */
    public function isAuthenticationKey(): bool
    {
        return $this === self::SYMMETRIC_AUTHENTICATION_KEY;
    }

    /**
     * Check if this is a public key.
     */
    public function isPublicKey(): bool
    {
        return match ($this) {
            self::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::SYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::SYMMETRIC_SIGNATURE_PUBLIC_KEY => true,
            default => false,
        };
    }

    /**
     * Check if this is a secret/private key.
     */
    public function isSecretKey(): bool
    {
        return match ($this) {
            self::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::ASYMMETRIC_SIGNATURE_SECRET_KEY,
            self::SYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::SYMMETRIC_SIGNATURE_SECRET_KEY => true,
            default => false,
        };
    }

    /**
     * Create KeyType from legacy string value.
     * 
     * @throws \ValueError if the string doesn't match any enum case
     */
    public static function fromString(string $type): self
    {
        return self::from($type);
    }

    /**
     * Get the string value (for backward compatibility and array usage).
     */
    public function toString(): string
    {
        return $this->value;
    }

    // ========================================================================
    // Static helper methods for getting arrays of key types
    // ========================================================================

    /**
     * Get all symmetric key types as an array of KeyType enums.
     * 
     * @return array<KeyType>
     */
    public static function allSymmetric(): array
    {
        return [
            self::SYMMETRIC_AUTHENTICATION_KEY,
            self::SYMMETRIC_ENCRYPTION_KEY,
            self::SYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::SYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::SYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::SYMMETRIC_SIGNATURE_SECRET_KEY,
        ];
    }

    /**
     * Get all asymmetric key types as an array of KeyType enums.
     * 
     * @return array<KeyType>
     */
    public static function allAsymmetric(): array
    {
        return [
            self::ASYMMETRIC_ENCRYPTION_KEY_PAIR,
            self::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::ASYMMETRIC_SIGNATURE_KEY_PAIR,
            self::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::ASYMMETRIC_SIGNATURE_SECRET_KEY,
        ];
    }

    /**
     * Get all encryption key types.
     * 
     * @return array<KeyType>
     */
    public static function allEncryption(): array
    {
        return [
            self::SYMMETRIC_ENCRYPTION_KEY,
            self::SYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::SYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::ASYMMETRIC_ENCRYPTION_KEY_PAIR,
            self::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
        ];
    }

    /**
     * Get all signature key types.
     * 
     * @return array<KeyType>
     */
    public static function allSignature(): array
    {
        return [
            self::SYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::SYMMETRIC_SIGNATURE_SECRET_KEY,
            self::ASYMMETRIC_SIGNATURE_KEY_PAIR,
            self::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::ASYMMETRIC_SIGNATURE_SECRET_KEY,
        ];
    }

    /**
     * Get all authentication key types.
     * 
     * @return array<KeyType>
     */
    public static function allAuthentication(): array
    {
        return [
            self::SYMMETRIC_AUTHENTICATION_KEY,
        ];
    }

    /**
     * Get all key pair types.
     * 
     * @return array<KeyType>
     */
    public static function allKeyPairs(): array
    {
        return [
            self::ASYMMETRIC_ENCRYPTION_KEY_PAIR,
            self::ASYMMETRIC_SIGNATURE_KEY_PAIR,
        ];
    }

    /**
     * Get all public key types.
     * 
     * @return array<KeyType>
     */
    public static function allPublicKeys(): array
    {
        return [
            self::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            self::SYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            self::SYMMETRIC_SIGNATURE_PUBLIC_KEY,
        ];
    }

    /**
     * Get all secret/private key types.
     * 
     * @return array<KeyType>
     */
    public static function allSecretKeys(): array
    {
        return [
            self::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::ASYMMETRIC_SIGNATURE_SECRET_KEY,
            self::SYMMETRIC_ENCRYPTION_SECRET_KEY,
            self::SYMMETRIC_SIGNATURE_SECRET_KEY,
        ];
    }

    /**
     * Convert an array of KeyType enums to their string values.
     * 
     * @param array<KeyType> $types
     * @return array<string>
     */
    public static function toStringArray(array $types): array
    {
        return array_map(fn(KeyType $type) => $type->value, $types);
    }

    /**
     * Convert an array of string values to KeyType enums.
     * 
     * @param array<string> $strings
     * @return array<KeyType>
     * @throws \ValueError if any string doesn't match an enum case
     */
    public static function fromStringArray(array $strings): array
    {
        return array_map(fn(string $str) => self::from($str), $strings);
    }
}
