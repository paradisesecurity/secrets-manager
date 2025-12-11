<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

/**
 * Interface for checksum value objects.
 * 
 * Checksums provide data integrity verification through cryptographic hashing
 * and digital signatures. This implementation uses BLAKE2b-512 checksums
 * (88 bytes base64-encoded) and Ed25519 signatures (88 bytes base64-encoded).
 * 
 * Design pattern: Value Object
 * - Immutable once created
 * - Self-validating
 * - Equality by value, not identity
 * 
 * @see https://en.wikipedia.org/wiki/Checksum
 * @see https://en.wikipedia.org/wiki/BLAKE_(hash_function)
 */
interface ChecksumInterface
{
    /**
     * Length of BLAKE2b-512 checksum in bytes (base64-encoded).
     * 
     * BLAKE2b-512 produces 64 bytes raw, which is 88 bytes base64-encoded.
     */
    public const CHECKSUM_LENGTH_BYTES = 88;

    /**
     * Length of Ed25519 signature in bytes (base64-encoded).
     * 
     * Ed25519 signatures are 64 bytes raw, which is 88 bytes base64-encoded.
     */
    public const SIGNATURE_LENGTH_BYTES = 88;

    /**
     * Combined length of checksum and signature.
     */
    public const COMBINED_LENGTH_BYTES = self::CHECKSUM_LENGTH_BYTES + self::SIGNATURE_LENGTH_BYTES;

    /**
     * Gets the checksum hash.
     * 
     * @return string BLAKE2b-512 checksum (88 bytes, base64-encoded)
     */
    public function getChecksum(): string;

    /**
     * Gets the cryptographic signature.
     * 
     * @return string Ed25519 signature (88 bytes, base64-encoded)
     */
    public function getSignature(): string;

    /**
     * Converts checksum and signature to file format.
     * 
     * File format: checksum concatenated with signature (176 bytes total)
     * 
     * @return string Combined checksum and signature
     */
    public function toString(): string;

    /**
     * Checks equality with another checksum.
     * 
     * Two checksums are equal if both checksum and signature match.
     * 
     * @param ChecksumInterface $other Checksum to compare
     * @return bool True if equal, false otherwise
     */
    public function equals(ChecksumInterface $other): bool;

    /**
     * Creates checksum from combined string (checksum + signature).
     * 
     * @param string $combined Combined checksum and signature
     * @return static New checksum instance
     * @throws InvalidSignatureOrChecksumException If format invalid
     */
    public static function fromString(string $combined): static;

    /**
     * Creates checksum from separate checksum and signature.
     * 
     * @param string $checksum Checksum hash
     * @param string $signature Cryptographic signature
     * @return static New checksum instance
     * @throws InvalidSignatureOrChecksumException If format invalid
     */
    public static function fromParts(string $checksum, string $signature): static;
}
