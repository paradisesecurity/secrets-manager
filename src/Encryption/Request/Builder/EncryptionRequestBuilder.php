<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request\Builder;

use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\FileEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

/**
 * Builder for creating encryption requests with flexible validation.
 * 
 * Provides operation-specific build methods that set appropriate
 * validation requirements automatically.
 * 
 * Provides a fluent interface for constructing complex encryption requests with clear intent and validation.
 * 
 * Example:
 * ```
 * $request = EncryptionRequestBuilder::create()
 *     ->withKey($encryptionKey)
 *     ->withKey($signatureKey)
 *     ->asymmetric()
 *     ->withAdditionalData('user-id:123')
 *     ->withEncoding('base64')
 *     ->buildForMessage($message);
 * 
 * // Encrypt: requires keys and output file
 * $request = EncryptionRequestBuilder::create()
 *     ->withKey($key)
 *     ->buildForFileEncryption($input, $output);
 * 
 * // Checksum: keys optional, no output file
 * $request = EncryptionRequestBuilder::create()
 *     ->buildForChecksum($input);
 * 
 * // With optional key for authenticated checksum
 * $request = EncryptionRequestBuilder::create()
 *     ->withKey($authenticationKey)  // Optional
 *     ->buildForChecksum($readOnlyFile);
 * 
 * // Sign: requires keys, no output file
 * $request = EncryptionRequestBuilder::create()
 *     ->withKey($privateKey)
 *     ->buildForSignature($input);
 * 
 * // Verification (Keys required, no output file)
 * $request = EncryptionRequestBuilder::create()
 *     ->withKey($publicKey)
 *     ->withSignature($signatureToVerify)
 *     ->buildForVerification($inputFile);
 * 
 * // Force keys to be optional for a custom operation
 * $request = EncryptionRequestBuilder::create()
 *     ->keysOptional()
 *     ->buildForChecksum($file);
 * 
 * // Force output file to be optional
 * $request = EncryptionRequestBuilder::create()
 *     ->withKey($key)
 *     ->outputFileOptional()
 *     ->buildForCustomOperation($input, null);
 * 
 * ```
 */
final class EncryptionRequestBuilder
{
    /** @var array<KeyInterface> */
    private array $keys = [];

    private ?string $encoding = null;
    private ?bool $chooseEncoder = null;
    private bool $decode = false;
    private ?string $additionalData = null;
    private bool $asymmetric = false;
    private ?string $mac = null;
    private ?string $signature = null;
    private ?string $version = null;

    /** @var array<string, mixed> */
    private array $configuration = [];

    // Validation flags (can be overridden)
    private ?bool $requiresKeys = null;
    private ?bool $requiresOutputFile = null;

    private function __construct()
    {
    }

    /**
     * Creates a new builder instance.
     */
    public static function create(): self
    {
        return new self();
    }

    /**
     * Adds a key to the request.
     */
    public function withKey(KeyInterface $key): self
    {
        $this->keys[] = $key;
        return $this;
    }

    /**
     * Adds multiple keys to the request.
     * 
     * @param array<KeyInterface> $keys
     */
    public function withKeys(array $keys): self
    {
        foreach ($keys as $key) {
            if ($key instanceof KeyInterface) {
                $this->keys[] = $key;
            }
        }
        return $this;
    }

    /**
     * Explicitly marks keys as required.
     * 
     * Overrides default behavior for operation-specific builders.
     */
    public function requireKeys(bool $required = true): self
    {
        $this->requiresKeys = $required;
        return $this;
    }

    /**
     * Explicitly marks keys as optional.
     * 
     * Useful when you want to allow operations without keys.
     */
    public function keysOptional(): self
    {
        $this->requiresKeys = false;
        return $this;
    }

    /**
     * Explicitly marks output file as required.
     */
    public function requireOutputFile(bool $required = true): self
    {
        $this->requiresOutputFile = $required;
        return $this;
    }

    /**
     * Explicitly marks output file as optional.
     */
    public function outputFileOptional(): self
    {
        $this->requiresOutputFile = false;
        return $this;
    }

    /**
     * Sets encoding format.
     */
    public function withEncoding(string $encoding): self
    {
        $this->encoding = $encoding;
        return $this;
    }

    /**
     * Sets encoder choice flag.
     */
    public function withEncoderChoice(bool $choose): self
    {
        $this->chooseEncoder = $choose;
        return $this;
    }

    /**
     * Enables input decoding.
     */
    public function withDecode(bool $decode = true): self
    {
        $this->decode = $decode;
        return $this;
    }

    /**
     * Sets additional authenticated data.
     */
    public function withAdditionalData(string $data): self
    {
        $this->additionalData = $data;
        return $this;
    }

    /**
     * Enables asymmetric cryptography.
     */
    public function asymmetric(bool $asymmetric = true): self
    {
        $this->asymmetric = $asymmetric;
        return $this;
    }

    /**
     * Enables symmetric cryptography.
     */
    public function symmetric(): self
    {
        $this->asymmetric = false;
        return $this;
    }

    /**
     * Sets MAC for verification.
     */
    public function withMac(string $mac): self
    {
        $this->mac = $mac;
        return $this;
    }

    /**
     * Sets signature for verification.
     */
    public function withSignature(string $signature): self
    {
        $this->signature = $signature;
        return $this;
    }

    /**
     * Sets library version.
     */
    public function withVersion(string $version): self
    {
        $this->version = $version;
        return $this;
    }

    /**
     * Adds custom configuration.
     */
    public function withConfiguration(string $key, mixed $value): self
    {
        $this->configuration[$key] = $value;
        return $this;
    }

    // ==================== Operation-Specific Builders ====================

    /**
     * Builds request for message encryption/decryption.
     * 
     * Requirements:
     * - Keys: REQUIRED
     * 
     * @param HiddenString $message Message to encrypt/decrypt
     */
    public function buildForMessage(HiddenString $message): MessageEncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: true
        );

        return new MessageEncryptionRequest($message, $this->keys, $config);
    }

    /**
     * Builds request for file encryption/decryption.
     * 
     * Requirements:
     * - Keys: REQUIRED
     * - Output file: REQUIRED
     * 
     * @param mixed $inputFile Input file path or stream
     * @param mixed $outputFile Output file path or stream
     */
    public function buildForFileEncryption(mixed $inputFile, mixed $outputFile): FileEncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: true,
            requiresOutputFile: true
        );

        return new FileEncryptionRequest($inputFile, $outputFile, $this->keys, $config);
    }

    /**
     * Builds request for file decryption.
     * 
     * Alias for buildForFileEncryption with clearer intent.
     * 
     * Requirements:
     * - Keys: REQUIRED
     * - Output file: REQUIRED
     */
    public function buildForFileDecryption(mixed $inputFile, mixed $outputFile): FileEncryptionRequest
    {
        return $this->buildForFileEncryption($inputFile, $outputFile);
    }

    /**
     * Builds request for file checksum generation.
     * 
     * Requirements:
     * - Keys: OPTIONAL (can use authentication key if provided)
     * - Output file: NOT REQUIRED (checksum is returned as string)
     * 
     * @param mixed $inputFile File to generate checksum for
     */
    public function buildForChecksum(mixed $inputFile): FileEncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: false,       // Keys are optional for checksum
            requiresOutputFile: false  // No output file needed
        );

        return new FileEncryptionRequest($inputFile, null, $this->keys, $config);
    }

    /**
     * Builds request for digital signature generation.
     * 
     * Requirements:
     * - Keys: REQUIRED (private/secret key)
     * - Output file: NOT REQUIRED (signature is returned as string)
     * 
     * @param mixed $inputFile File to sign
     */
    public function buildForSignature(mixed $inputFile): FileEncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: true,        // Signing requires private key
            requiresOutputFile: false  // Signature returned as string
        );

        return new FileEncryptionRequest($inputFile, null, $this->keys, $config);
    }

    /**
     * Builds request for signature verification.
     * 
     * Requirements:
     * - Keys: REQUIRED (public key)
     * - Output file: NOT REQUIRED (returns boolean)
     * 
     * @param mixed $inputFile File to verify
     */
    public function buildForVerification(mixed $inputFile): FileEncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: true,        // Verification requires public key
            requiresOutputFile: false  // Returns boolean result
        );

        return new FileEncryptionRequest($inputFile, null, $this->keys, $config);
    }

    /**
     * Builds request for file sealing (anonymous encryption).
     * 
     * Requirements:
     * - Keys: REQUIRED (recipient's public key)
     * - Output file: REQUIRED
     * 
     * @param mixed $inputFile File to seal
     * @param mixed $outputFile Sealed output file
     */
    public function buildForSealing(mixed $inputFile, mixed $outputFile): FileEncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: true,
            requiresOutputFile: true
        );

        return new FileEncryptionRequest($inputFile, $outputFile, $this->keys, $config);
    }

    /**
     * Builds request for unsealing (anonymous decryption).
     * 
     * Requirements:
     * - Keys: REQUIRED (recipient's private key)
     * - Output file: REQUIRED
     * 
     * @param mixed $inputFile Sealed file to unseal
     * @param mixed $outputFile Unsealed output file
     */
    public function buildForUnsealing(mixed $inputFile, mixed $outputFile): FileEncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: true,
            requiresOutputFile: true
        );

        return new FileEncryptionRequest($inputFile, $outputFile, $this->keys, $config);
    }

    /**
     * Builds a generic encryption request with manual validation control.
     * 
     * Use this when operation-specific builders don't fit your use case.
     * You must explicitly set validation requirements.
     */
    public function build(): EncryptionRequest
    {
        $config = $this->buildConfiguration(
            requiresKeys: $this->requiresKeys ?? true,
            requiresOutputFile: null
        );

        return new EncryptionRequest($this->keys, $config);
    }

    /**
     * Builds configuration array with validation flags.
     * 
     * @param bool $requiresKeys Whether keys are required
     * @param bool|null $requiresOutputFile Whether output file is required (null if N/A)
     */
    private function buildConfiguration(
        bool $requiresKeys,
        ?bool $requiresOutputFile = null
    ): array {
        $config = [];

        // Apply explicit overrides if set
        if ($this->requiresKeys !== null) {
            $requiresKeys = $this->requiresKeys;
        }
        if ($this->requiresOutputFile !== null && $requiresOutputFile !== null) {
            $requiresOutputFile = $this->requiresOutputFile;
        }

        // Set validation flags
        $config[EncryptionRequestInterface::REQUIRES_KEYS] = $requiresKeys;
        if ($requiresOutputFile !== null) {
            $config[EncryptionRequestInterface::REQUIRES_OUTPUT_FILE] = $requiresOutputFile;
        }

        // Add operational configuration
        if ($this->encoding !== null) {
            $config[EncryptionRequestInterface::ENCODING] = $this->encoding;
        }
        if ($this->chooseEncoder !== null) {
            $config[EncryptionRequestInterface::CHOOSE_ENCODER] = $this->chooseEncoder;
        }
        if ($this->decode) {
            $config[EncryptionRequestInterface::DECODE] = $this->decode;
        }
        if ($this->additionalData !== null) {
            $config[EncryptionRequestInterface::ADDITIONAL_DATA] = $this->additionalData;
        }
        if ($this->asymmetric) {
            $config[EncryptionRequestInterface::ASYMMETRIC] = $this->asymmetric;
        }
        if ($this->mac !== null) {
            $config[EncryptionRequestInterface::MAC] = $this->mac;
        }
        if ($this->signature !== null) {
            $config[EncryptionRequestInterface::SIGNATURE] = $this->signature;
        }
        if ($this->version !== null) {
            $config[EncryptionRequestInterface::VERSION] = $this->version;
        }

        return array_merge($config, $this->configuration);
    }
}
