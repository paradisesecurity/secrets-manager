<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

/**
 * File encryption request implementation with flexible validation.
 * 
 * Supports operations that don't require output files (e.g., checksum).
 * 
 * Handles encryption/decryption of files or streams.
 * Input and output can be:
 * - File paths (string)
 * - Stream resources (resource)
 * - Flysystem StreamInterface objects
 * 
 * Example:
 * ```
 * $request = new FileEncryptionRequest(
 *     '/path/to/input.txt',
 *     '/path/to/output.enc',
 *     $encryptionKey
 * );
 * ```
 */
final class FileEncryptionRequest extends EncryptionRequest implements FileEncryptionRequestInterface
{
    /**
     * @param mixed $inputFile Input file path or stream
     * @param mixed $outputFile Output file path, stream, or null if not required
     * @param KeyInterface|array<KeyInterface>|array<empty> $keys Encryption keys or empty array
     * @param array<string, mixed> $config Additional configuration
     */
    public function __construct(
        private mixed $inputFile,
        private mixed $outputFile,
        KeyInterface|array $keys,
        array $config = [],
    ) {
        // Check if output file is explicitly not required
        $this->requiresOutputFile = $config[self::REQUIRES_OUTPUT_FILE] ?? true;

        parent::__construct($keys, $config);
        $this->validateFiles();
    }

    public function getInputFile(): mixed
    {
        return $this->inputFile;
    }

    public function getOutputFile(): mixed
    {
        return $this->outputFile;
    }

    /**
     * Checks if this request requires an output file.
     * 
     * @return bool True if output file is mandatory, false if optional
     */
    public function requiresOutputFile(): bool
    {
        return $this->requiresOutputFile;
    }

    /**
     * Validates file parameters based on requirements.
     */
    private function validateFiles(): void
    {
        if ($this->inputFile === null) {
            throw new \InvalidArgumentException('Input file cannot be null');
        }

        // Only validate output file if required for this operation
        if ($this->requiresOutputFile && $this->outputFile === null) {
            throw new \InvalidArgumentException(
                'This operation requires an output file, but none was provided'
            );
        }
    }
}
