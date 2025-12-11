<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption;

use ParadiseSecurity\Component\SecretsManager\Adapter\AbstractAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\Validator\EncryptionRequestValidator;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnresolvedKeyProviderException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProviderInterface;
use ParagonIE\HiddenString\HiddenString;

use function implode;

/**
 * Abstract base for encryption adapters implementing Template Method pattern.
 * Provides common validation, error handling, and utility methods
 * that all encryption adapters share. Follows defensive programming
 * principles by validating preconditions before operations.
 * 
 * Custom adapters should extend this class and implement the abstract methods
 * for their specific encryption library.
 * 
 * @see EncryptionAdapterInterface for the contract all adapters must follow
 */
abstract class AbstractEncryptionAdapter extends AbstractAdapter implements EncryptionAdapterInterface
{
    protected EncryptionRequestValidator $validator;

    public function __construct(
        protected AdapterBasedKeyProviderInterface $adapterBasedKeyProvider
    ) {
        parent::__construct();
        $this->validator = new EncryptionRequestValidator();
    }

    /**
     * Gets the required encryption key type for this adapter.
     * 
     * @return string Key type identifier (e.g., 'halite_key', 'sodium_key')
     */
    abstract public function getRequiredEncryptionKeyType(): string;

    abstract public function checksum(EncryptionRequestInterface $request): string;

    abstract public function seal(EncryptionRequestInterface $request): string|int;

    abstract public function unseal(EncryptionRequestInterface $request): HiddenString|bool;

    abstract public function sign(EncryptionRequestInterface $request): string;

    abstract public function signAndEncrypt(EncryptionRequestInterface $request): string;

    abstract public function verifyAndDecrypt(EncryptionRequestInterface $request): HiddenString;

    abstract public function authenticate(EncryptionRequestInterface $request): string;

    /**
     * Template method for encryption operations.
     * Handles key resolution and delegates to specific implementation.
     */
    final public function encrypt(EncryptionRequestInterface $request): string|int
    {
        // Validate request - keys and output file required
        $this->validateEncryptRequest($request, 'encrypt');
        
        return $this->executeOperation(function () use ($request) {
            if ($request->isAsymmetric()) {
                return $this->performAsymmetricEncryption($request);
            }

            return $this->performSymmetricEncryption($request);
        }, 'encrypt');
    }

    /**
     * Template method for decryption operations.
     */
    final public function decrypt(EncryptionRequestInterface $request): HiddenString|bool
    {
        // Validate request
        $this->validateDecryptRequest($request, 'decrypt');
        
        return $this->executeOperation(function () use ($request) {
            if ($request->isAsymmetric()) {
                return $this->performAsymmetricDecryption($request);
            }

            return $this->performSymmetricDecryption($request);
        }, 'decrypt');
    }

    /**
     * Template method for verification operations.
     */
    final public function verify(EncryptionRequestInterface $request): bool
    {
        // Validate request - requires public key and signature
        $this->validateVerifyRequest($request);

        return $this->executeOperation(function () use ($request) {
            if ($request->isAsymmetric()) {
                return $this->performAsymmetricVerification($request);
            }

            return $this->performSymmetricVerification($request);
        }, 'verify');
    }

    // Abstract methods that must be implemented by concrete adapters

    /**
     * Performs symmetric encryption using the adapter's encryption library.
     * 
     * @param EncryptionRequestInterface $request The encryption request
     * @return string|int Encrypted data or bytes written
     * @throws UnableToEncryptMessageException If encryption fails
     */
    abstract protected function performSymmetricEncryption(EncryptionRequestInterface $request): string|int;
    
    /**
     * Performs symmetric decryption using the adapter's encryption library.
     * 
     * @param EncryptionRequestInterface $request The decryption request
     * @return HiddenString|bool Decrypted data or success status
     * @throws UnableToEncryptMessageException If decryption fails
     */
    abstract protected function performSymmetricDecryption(EncryptionRequestInterface $request): HiddenString|bool;
    
    /**
     * Performs asymmetric encryption using the adapter's encryption library.
     * 
     * @param EncryptionRequestInterface $request The encryption request
     * @return string|int Encrypted data or bytes written
     * @throws UnableToEncryptMessageException If encryption fails
     */
    abstract protected function performAsymmetricEncryption(EncryptionRequestInterface $request): string|int;
    
    /**
     * Performs asymmetric decryption using the adapter's encryption library.
     * 
     * @param EncryptionRequestInterface $request The decryption request
     * @return HiddenString|bool Decrypted data or success status
     * @throws UnableToEncryptMessageException If decryption fails
     */
    abstract protected function performAsymmetricDecryption(EncryptionRequestInterface $request): HiddenString|bool;
    
    /**
     * Performs symmetric verification (MAC verification).
     * 
     * @param EncryptionRequestInterface $request The verification request
     * @return bool True if valid, false otherwise
     * @throws UnableToEncryptMessageException If verification operation fails
     */
    abstract protected function performSymmetricVerification(EncryptionRequestInterface $request): bool;
    
    /**
     * Performs asymmetric verification (signature verification).
     * 
     * @param EncryptionRequestInterface $request The verification request
     * @return bool True if valid, false otherwise
     * @throws UnableToEncryptMessageException If verification operation fails
     */

    // Hook methods with default implementations (can be overridden)

    /**
     * Validates request for encryption operations.
     * 
     * Default validation:
     * - Keys are required
     * - Keys must match this adapter
     * - Output file required if file operation
     * 
     * Override to add adapter-specific validation.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    protected function validateEncryptRequest(
        EncryptionRequestInterface $request,
        string $operation = 'encrypt'
    ): void {
        // Validate keys if required by request
        $this->validator->validateKeysIfRequired($request, $operation);

        // If keys are present, validate they're for this adapter
        if ($request->hasKeys()) {
            $this->validator->validateKeysMatchAdapter(
                $request,
                $this->getName(),
                $operation
            );
        }

        // Validate version compatibility
        $this->validator->validateVersionCompatibility(
            $request,
            $this->getVersion(),
            $operation
        );

        // Validate file-specific requirements
        if ($request instanceof FileEncryptionRequestInterface) {
            $this->validator->validateHasInputFile($request, $operation);
            $this->validator->validateOutputFileIfRequired($request, $operation);
        }
    }

    /**
     * Validates request for decryption operations.
     * 
     * Same as encrypt, but can be overridden for different requirements.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @param string $operation Operation name for error messages
     * @throws InvalidEncryptionRequestException If validation fails
     */
    protected function validateDecryptRequest(
        EncryptionRequestInterface $request,
        string $operation = 'decrypt'
    ): void {
        $this->validateEncryptRequest($request, $operation);
    }

    /**
     * Validates request for checksum operations.
     * 
     * Checksum operations:
     * - Keys are OPTIONAL (request decides via requiresKeys())
     * - Input file required
     * - Output file NOT required
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @throws InvalidEncryptionRequestException If validation fails
     */
    protected function validateChecksumRequest(
        EncryptionRequestInterface $request
    ): void {
        $operation = 'checksum';

        // Keys are optional for checksum, but validate if required by request
        $this->validator->validateKeysIfRequired($request, $operation);

        // If keys are present, validate them
        if ($request->hasKeys()) {
            $this->validator->validateKeysMatchAdapter(
                $request,
                $this->getName(),
                $operation
            );

            // For authenticated checksums, validate key type
            $allowedKeyTypes = [
                KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY,
                KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            ];
            $this->validator->validateKeyType($request, $allowedKeyTypes, $operation);
        }

        // Validate file requirements
        if ($request instanceof FileEncryptionRequestInterface) {
            $this->validator->validateHasInputFile($request, $operation);
            // Output file is never required for checksum
        }
    }

    /**
     * Validates request for signing operations.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @throws InvalidEncryptionRequestException If validation fails
     */
    protected function validateSignRequest(
        EncryptionRequestInterface $request
    ): void {
        $operation = 'sign';

        // Signing always requires keys
        $this->validator->validateHasKeys($request, $operation);
        $this->validator->validateKeysMatchAdapter($request, $this->getName(), $operation);

        // Validate key type
        $allowedKeyTypes = [
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY,
        ];
        $this->validator->validateKeyType($request, $allowedKeyTypes, $operation);

        // File validation
        if ($request instanceof FileEncryptionRequestInterface) {
            $this->validator->validateHasInputFile($request, $operation);
            // Output file not required for sign (signature is returned)
        }
    }

    /**
     * Validates request for verification operations.
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @throws InvalidEncryptionRequestException If validation fails
     */
    protected function validateVerifyRequest(
        EncryptionRequestInterface $request
    ): void {
        $operation = 'verify';

        // Verification requires keys and signature/MAC
        $this->validator->validateHasKeys($request, $operation);
        $this->validator->validateKeysMatchAdapter($request, $this->getName(), $operation);
        $this->validator->validateHasSignature($request, $operation);

        // Validate key type
        $allowedKeyTypes = [
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY,
        ];
        $this->validator->validateKeyType($request, $allowedKeyTypes, $operation);

        // File validation
        if ($request instanceof FileEncryptionRequestInterface) {
            $this->validator->validateHasInputFile($request, $operation);
            // Output file not required for verify (returns boolean)
        }
    }

    /**
     * Validates request for seal operations (anonymous encryption).
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @throws InvalidEncryptionRequestException If validation fails
     */
    protected function validateSealRequest(
        EncryptionRequestInterface $request
    ): void {
        $operation = 'seal';

        $this->validator->validateHasKeys($request, $operation);
        $this->validator->validateKeysMatchAdapter($request, $this->getName(), $operation);

        // Sealing requires public key
        $allowedKeyTypes = [
            KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
        ];
        $this->validator->validateKeyType($request, $allowedKeyTypes, $operation);

        // File validation
        if ($request instanceof FileEncryptionRequestInterface) {
            $this->validator->validateHasInputFile($request, $operation);
            $this->validator->validateOutputFileIfRequired($request, $operation);
        }
    }

    /**
     * Validates request for unseal operations (anonymous decryption).
     * 
     * @param EncryptionRequestInterface $request Request to validate
     * @throws InvalidEncryptionRequestException If validation fails
     */
    protected function validateUnsealRequest(
        EncryptionRequestInterface $request
    ): void {
        $operation = 'unseal';

        $this->validator->validateHasKeys($request, $operation);
        $this->validator->validateKeysMatchAdapter($request, $this->getName(), $operation);

        // Unsealing requires secret key
        $allowedKeyTypes = [
            KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
        ];
        $this->validator->validateKeyType($request, $allowedKeyTypes, $operation);

        // File validation
        if ($request instanceof FileEncryptionRequestInterface) {
            $this->validator->validateHasInputFile($request, $operation);
            $this->validator->validateOutputFileIfRequired($request, $operation);
        }
    }

    // Common utility methods available to all adapters

    /**
     * Gets the appropriate key factory adapter for this encryption adapter.
     * 
     * @param string $keyType The type of key needed
     * @return KeyFactoryAdapterInterface
     * @throws UnresolvedKeyProviderException If no provider supports the key type
     */
    protected function getAdapterAppropriateKey(string $keyType): KeyFactoryAdapterInterface
    {
        if (!$this->adapterBasedKeyProvider->supports($keyType)) {
            throw new UnresolvedKeyProviderException(
                "No key provider supports key type: {$keyType}"
            );
        }

        return $this->adapterBasedKeyProvider->getSupportedAdapter($keyType);
    }

    /**
     * Throws an exception for missing required keys.
     * 
     * @param array $keyTypes Array of missing key type identifiers
     * @throws UnableToEncryptMessageException
     */
    protected function unableToEncryptMessageWithMissingKey(array $keyTypes): void
    {
        $formattedTypes = array_map(
            fn($type) => $this->transformSnakeCaseIntoWord($type),
            $keyTypes
        );
        
        $keyTypesList = implode(", ", $formattedTypes);
        throw UnableToEncryptMessageException::withMissingKey($keyTypesList);
    }

    /**
     * Finds a key matching one of the allowed types.
     * 
     * @param array $keys Available keys
     * @param array $allowedTypes Acceptable key types
     * @return mixed The first matching key
     * @throws UnableToEncryptMessageException If no matching key found
     */
    protected function findKeyByType(array $keys, array $allowedTypes): mixed
    {
        foreach ($keys as $key) {
            if (in_array($key->getType(), $allowedTypes, true)) {
                return $key;
            }
        }

        throw new UnableToEncryptMessageException(
            "Required key type not found. Expected one of: " . implode(', ', $allowedTypes)
        );
    }

    /**
     * Wraps operation execution with consistent error handling.
     * 
     * Provides a consistent try-catch pattern for all operations.
     * 
     * @param callable $operation Operation to execute
     * @param string $operationName Operation name for error messages
     * @return mixed Operation result
     * @throws UnableToEncryptMessageException If operation fails
     */
    protected function executeOperation(callable $operation, string $operationName): mixed
    {
        try {
            return $operation();
        } catch (InvalidEncryptionRequestException $exception) {
            // Re-throw validation errors as-is
            throw $exception;
        } catch (UnableToEncryptMessageException $exception) {
            // Re-throw encryption errors as-is
            throw $exception;
        } catch (\Exception $exception) {
            // Wrap unexpected exceptions
            throw new UnableToEncryptMessageException(
                "Operation '{$operationName}' failed: {$exception->getMessage()}",
                $exception
            );
        }
    }
}
