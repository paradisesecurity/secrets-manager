<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

/**
 * Exception thrown when checksum or signature validation fails.
 */
class InvalidSignatureOrChecksumException extends \InvalidArgumentException
{
    public static function invalidCombinedLength(int $actual, int $expected): self
    {
        return new self(
            "Invalid combined checksum length. Expected {$expected} bytes, got {$actual} bytes. " .
            "Combined format should be checksum (88 bytes) + signature (88 bytes)."
        );
    }

    public static function invalidChecksumLength(int $actual, int $expected): self
    {
        return new self(
            "Invalid checksum length. Expected {$expected} bytes, got {$actual} bytes. " .
            "BLAKE2b-512 checksums are 88 bytes when base64-encoded."
        );
    }

    public static function invalidSignatureLength(int $actual, int $expected): self
    {
        return new self(
            "Invalid signature length. Expected {$expected} bytes, got {$actual} bytes. " .
            "Ed25519 signatures are 88 bytes when base64-encoded."
        );
    }

    public static function invalidChecksumFormat(): self
    {
        return new self(
            "Invalid checksum format. Checksum must be valid base64-encoded data."
        );
    }

    public static function invalidSignatureFormat(): self
    {
        return new self(
            "Invalid signature format. Signature must be valid base64-encoded data."
        );
    }

    public static function checksumMismatch(): self
    {
        return new self(
            "Checksum verification failed. The calculated checksum does not match the stored checksum."
        );
    }

    public static function signatureVerificationFailed(): self
    {
        return new self(
            "Signature verification failed. The signature is invalid or the data has been modified."
        );
    }
}
