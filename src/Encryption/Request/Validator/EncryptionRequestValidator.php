<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request\Validator;

use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\FileEncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\InvalidEncryptionRequestException;

/**
 * Validates encryption requests for adapter operations.
 * 
 * Implements defensive programming by validating preconditions
 * before operations are executed. This prevents runtime errors
 * and provides clear error messages.
 * 
 * Validation strategies:
 * - Fail fast: Validate early, before expensive operations
 * - Clear errors: Provide actionable error messages
 * - Context-aware: Different operations have different requirements
 */
final class EncryptionRequestValidator
{
    /**
     * Validates that request has required keys for the operation.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateHasKeys(
        EncryptionRequestInterface $request,
        string $operation
    ): void {
        if (!$request->hasKeys()) {
            throw new InvalidEncryptionRequestException(
                "Operation '{$operation}' requires at least one encryption key, but none were provided."
            );
        }
    }

    /**
     * Validates that request has keys only if required by the operation.
     * 
     * Uses the request's own requiresKeys() flag for conditional validation.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateKeysIfRequired(
        EncryptionRequestInterface $request,
        string $operation
    ): void {
        if ($request->requiresKeys() && !$request->hasKeys()) {
            throw new InvalidEncryptionRequestException(
                "Operation '{$operation}' requires encryption keys, but none were provided."
            );
        }
    }

    /**
     * Validates that request has a specific key type.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param array<string> $allowedTypes Allowed key types
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateKeyType(
        EncryptionRequestInterface $request,
        array $allowedTypes,
        string $operation
    ): void {
        if (!$request->hasKeys()) {
            return; // Skip if no keys (handled by validateHasKeys)
        }

        $key = $request->getKey();
        $keyType = $key->getType();

        if (!in_array($keyType, $allowedTypes, true)) {
            $allowed = implode(', ', $allowedTypes);
            throw new InvalidEncryptionRequestException(
                "Operation '{$operation}' requires key type [{$allowed}], but got '{$keyType}'."
            );
        }
    }

    /**
     * Validates file encryption request has input file.
     * 
     * @param FileEncryptionRequestInterface $request Request to validate
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateHasInputFile(
        FileEncryptionRequestInterface $request,
        string $operation
    ): void {
        if ($request->getInputFile() === null) {
            throw new InvalidEncryptionRequestException(
                "Operation '{$operation}' requires an input file, but none was provided."
            );
        }
    }

    /**
     * Validates file encryption request has output file if required.
     * 
     * Uses the request's own requiresOutputFile() flag for conditional validation.
     * 
     * @param FileEncryptionRequestInterface $request Request to validate
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateOutputFileIfRequired(
        FileEncryptionRequestInterface $request,
        string $operation
    ): void {
        if ($request->requiresOutputFile() && $request->getOutputFile() === null) {
            throw new InvalidEncryptionRequestException(
                "Operation '{$operation}' requires an output file, but none was provided."
            );
        }
    }

    /**
     * Validates request has signature for verification operations.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateHasSignature(
        EncryptionRequestInterface $request,
        string $operation
    ): void {
        if ($request->getSignature() === null && $request->getMac() === null) {
            throw new InvalidEncryptionRequestException(
                "Operation '{$operation}' requires a signature or MAC for verification, but none was provided."
            );
        }
    }

    /**
     * Validates all keys in request match expected adapter.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param string $expectedAdapter Expected adapter name
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateKeysMatchAdapter(
        EncryptionRequestInterface $request,
        string $expectedAdapter,
        string $operation
    ): void {
        if (!$request->hasKeys()) {
            return; // Skip if no keys
        }

        foreach ($request->getKeys() as $index => $key) {
            $keyAdapter = $key->getAdapter();
            
            if ($keyAdapter !== $expectedAdapter) {
                throw new InvalidEncryptionRequestException(
                    "Operation '{$operation}' expected keys for adapter '{$expectedAdapter}', " .
                    "but key at index {$index} is for adapter '{$keyAdapter}'."
                );
            }
        }
    }

    /**
     * Validates request version matches adapter version.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param string $adapterVersion Adapter version
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    public function validateVersionCompatibility(
        EncryptionRequestInterface $request,
        string $adapterVersion,
        string $operation
    ): void {
        $requestVersion = $request->getVersion();
        
        if ($requestVersion === null) {
            return; // No specific version requested
        }

        if ($requestVersion !== $adapterVersion) {
            throw new InvalidEncryptionRequestException(
                "Operation '{$operation}' requires version '{$requestVersion}', " .
                "but adapter version is '{$adapterVersion}'."
            );
        }
    }
}
