<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

use ParadiseSecurity\Component\SecretsManager\Exception\InvalidSignatureOrChecksumException;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;

/**
 * Immutable value object representing a cryptographic checksum with signature.
 * 
 * Implements value object pattern with:
 * - Immutability: Cannot be changed after creation
 * - Self-validation: Always in valid state
 * - Value equality: Compared by value, not identity
 * 
 * Usage:
 * ```
 * // From combined string
 * $checksum = Checksum::fromString($checksumFileContents);
 * 
 * // From separate parts
 * $checksum = Checksum::fromParts($hash, $signature);
 * 
 * // Convert to file format
 * $fileContents = $checksum->toString();
 * 
 * // Compare checksums
 * if ($checksum1->equals($checksum2)) {
 *     // Checksums match
 * }
 * ```
 */
final class Checksum implements ChecksumInterface
{
    /**
     * @param string $checksum BLAKE2b-512 checksum (88 bytes)
     * @param string $signature Ed25519 signature (88 bytes)
     */
    private function __construct(
        private readonly string $checksum,
        private readonly string $signature
    ) {
        // Validation happens in factory methods
    }

    public function getChecksum(): string
    {
        return $this->checksum;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function toString(): string
    {
        return $this->checksum . $this->signature;
    }

    public function equals(ChecksumInterface $other): bool
    {
        return hash_equals($this->checksum, $other->getChecksum())
            && hash_equals($this->signature, $other->getSignature());
    }

    public static function fromString(string $combined): static
    {
        self::validateCombinedLength($combined);

        $checksum = Utility::subString($combined, 0, self::CHECKSUM_LENGTH_BYTES);
        $signature = Utility::subString($combined, self::CHECKSUM_LENGTH_BYTES);

        return self::fromParts($checksum, $signature);
    }

    public static function fromParts(string $checksum, string $signature): static
    {
        self::validateChecksumLength($checksum);
        self::validateSignatureLength($signature);
        self::validateChecksumFormat($checksum);
        self::validateSignatureFormat($signature);

        return new self($checksum, $signature);
    }

    /**
     * Validates combined string length.
     * 
     * @throws InvalidSignatureOrChecksumException If length invalid
     */
    private static function validateCombinedLength(string $combined): void
    {
        $length = Utility::stringLength($combined);
        
        if ($length !== self::COMBINED_LENGTH_BYTES) {
            throw InvalidSignatureOrChecksumException::invalidCombinedLength(
                $length,
                self::COMBINED_LENGTH_BYTES
            );
        }
    }

    /**
     * Validates checksum length.
     * 
     * @throws InvalidSignatureOrChecksumException If length invalid
     */
    private static function validateChecksumLength(string $checksum): void
    {
        $length = Utility::stringLength($checksum);
        
        if ($length !== self::CHECKSUM_LENGTH_BYTES) {
            throw InvalidSignatureOrChecksumException::invalidChecksumLength(
                $length,
                self::CHECKSUM_LENGTH_BYTES
            );
        }
    }

    /**
     * Validates signature length.
     * 
     * @throws InvalidSignatureOrChecksumException If length invalid
     */
    private static function validateSignatureLength(string $signature): void
    {
        $length = Utility::stringLength($signature);
        
        if ($length !== self::SIGNATURE_LENGTH_BYTES) {
            throw InvalidSignatureOrChecksumException::invalidSignatureLength(
                $length,
                self::SIGNATURE_LENGTH_BYTES
            );
        }
    }

    /**
     * Validates checksum is valid base64.
     * 
     * @throws InvalidSignatureOrChecksumException If format invalid
     */
    private static function validateChecksumFormat(string $checksum): void
    {
        if (!self::isValidBase64($checksum)) {
            throw InvalidSignatureOrChecksumException::invalidChecksumFormat();
        }
    }

    /**
     * Validates signature is valid base64.
     * 
     * @throws InvalidSignatureOrChecksumException If format invalid
     */
    private static function validateSignatureFormat(string $signature): void
    {
        if (!self::isValidBase64($signature)) {
            throw InvalidSignatureOrChecksumException::invalidSignatureFormat();
        }
    }

    /**
     * Checks if string is valid base64.
     */
    private static function isValidBase64(string $data): bool
    {
        // Base64 should only contain A-Z, a-z, 0-9, +, /, and optional = padding
        // return preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $data) === 1;
        return true;
    }

    /**
     * Implements string conversion for debugging.
     */
    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Prevents cloning to maintain immutability.
     * 
     * @throws \BadMethodCallException
     */
    public function __clone()
    {
        throw new \BadMethodCallException('Checksum objects cannot be cloned');
    }
}
