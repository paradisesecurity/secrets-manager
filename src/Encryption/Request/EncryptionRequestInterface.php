<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Trait\ConfigurationAwareInterface;

/**
 * Interface for encryption request objects.
 * 
 * Implements the Command pattern by encapsulating all information needed for an encryption/decryption operation.
 * 
 * This allows:
 * - Passing complex encryption parameters as a single object
 * - Type-safe parameter handling
 * - Extensibility without changing adapter signatures
 * - Separation of request construction from execution
 * 
 * Different operations have different requirements:
 * - encrypt/decrypt: Require keys and output file
 * - checksum: Optional keys, no output file needed
 * - sign: Requires keys, no output file needed
 * 
 * Request objects are immutable once constructed (fluent setters return new instances).
 * 
 * @see https://refactoring.guru/design-patterns/command
 */
interface EncryptionRequestInterface extends ConfigurationAwareInterface
{
    // Configuration keys
    public const ENCODING = 'encoding';
    public const CHOOSE_ENCODER = 'choose_encoder';
    public const DECODE = 'decode';
    public const ADDITIONAL_DATA = 'additional_data';
    public const MAC = 'mac';
    public const SIGNATURE = 'signature';
    public const VERSION = 'version';
    public const ASYMMETRIC = 'asymmetric';

    // Validation requirement flags
    public const REQUIRES_KEYS = 'requires_keys';
    public const REQUIRES_OUTPUT_FILE = 'requires_output_file';

    /**
     * Gets all cryptographic keys for this request.
     * 
     * @return array<KeyInterface> Array of keys (may be empty if keys not required)
     */
    public function getKeys(): array;

    /**
     * Gets the primary/first key from the keys array.
     * 
     * Convenience method for operations requiring a single key.
     * 
     * @return KeyInterface Primary key
     * @throws \RuntimeException If no keys available
     */
    public function getKey(): KeyInterface;

    /**
     * Checks if any keys are present.
     * 
     * @return bool True if keys exist, false otherwise
     */
    public function hasKeys(): bool;

    /**
     * Checks if this request requires keys to be valid.
     * 
     * @return bool True if keys are mandatory, false if optional
     */
    public function requiresKeys(): bool;

    /**
     * Gets encoding format for encrypted output.
     * 
     * Common values: 'base64', 'hex', 'raw'
     * 
     * @return string|null Encoding format or null for library default
     */
    public function getEncoding(): ?string;

    /**
     * Sets encoding format.
     * 
     * @param string|null $encoding Encoding format
     * @return static New instance with updated encoding
     */
    public function setEncoding(?string $encoding): static;

    /**
     * Gets encoder choice flag.
     * 
     * Some libraries allow choosing between multiple encoders.
     * 
     * @return bool|null Encoder choice or null for library default
     */
    public function chooseEncoder(): ?bool;

    /**
     * Sets encoder choice flag.
     * 
     * @param bool|null $choose Encoder choice
     * @return static New instance with updated flag
     */
    public function setChooseEncoder(?bool $choose): static;

    /**
     * Checks if input should be decoded before processing.
     * 
     * @return bool True if decode, false otherwise
     */
    public function shouldDecode(): bool;

    /**
     * Sets decode flag.
     * 
     * @param bool $decode Whether to decode input
     * @return static New instance with updated flag
     */
    public function setDecode(bool $decode): static;

    /**
     * Gets additional authenticated data (AAD).
     * 
     * Used in authenticated encryption schemes to bind metadata
     * to the encrypted data without encrypting it.
     * 
     * @return string Additional data (empty string if none)
     */
    public function getAdditionalData(): string;

    /**
     * Sets additional authenticated data.
     * 
     * @param string|null $data Additional data
     * @return static New instance with updated data
     */
    public function setAdditionalData(?string $data): static;

    /**
     * Checks if asymmetric cryptography should be used.
     * 
     * @return bool True for asymmetric, false for symmetric
     */
    public function isAsymmetric(): bool;

    /**
     * Sets asymmetric flag.
     * 
     * @param bool $asymmetric Whether to use asymmetric crypto
     * @return static New instance with updated flag
     */
    public function setAsymmetric(bool $asymmetric): static;

    /**
     * Gets library/algorithm version to use.
     * 
     * @return string|null Version string or null for current
     */
    public function getVersion(): ?string;

    /**
     * Sets library/algorithm version.
     * 
     * @param string|null $version Version string
     * @return static New instance with updated version
     */
    public function setVersion(?string $version): static;

    /**
     * Gets Message Authentication Code (MAC) for verification.
     * 
     * Used in symmetric authentication schemes.
     * 
     * @return string|null MAC value or null
     */
    public function getMac(): ?string;

    /**
     * Sets MAC value.
     * 
     * @param string|null $mac MAC value
     * @return static New instance with updated MAC
     */
    public function setMac(?string $mac): static;

    /**
     * Gets digital signature for verification.
     * 
     * Used in asymmetric signature schemes.
     * 
     * @return string|null Signature value or null
     */
    public function getSignature(): ?string;

    /**
     * Sets signature value.
     * 
     * @param string|null $signature Signature value
     * @return static New instance with updated signature
     */
    public function setSignature(?string $signature): static;

    /**
     * Gets all configuration as an associative array.
     * 
     * @return array<string, mixed> Configuration array
     */
    public function getConfiguration(): array;

    /**
     * Sets configuration value by key.
     * 
     * @param string $key Configuration key
     * @param mixed $value Configuration value
     * @return static New instance with updated configuration
     */
    public function setConfiguration(string $key, mixed $value): static;
}
