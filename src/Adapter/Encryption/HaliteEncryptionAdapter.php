<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite\HaliteAsymmetricCrypto;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite\HaliteConfigProcessor;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite\HaliteFileHandler;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite\HaliteKeyResolver;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite\HaliteSymmetricCrypto;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\HaliteKeyFactoryAdapter;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProviderInterface;
use ParagonIE\Halite\File as HaliteFile;
use ParagonIE\Halite\Halite;
use ParagonIE\HiddenString\HiddenString;

/**
 * Halite encryption adapter implementing the Template Method pattern.
 * Delegates specific operations to specialized service classes.
 */
final class HaliteEncryptionAdapter extends AbstractEncryptionAdapter
{
    public const ADAPTER_NAME = 'halite';
    public const CURRENT_VERSION = Halite::VERSION;

    private HaliteKeyResolver $keyResolver;
    private HaliteConfigProcessor $configProcessor;
    private HaliteFileHandler $fileHandler;
    private HaliteSymmetricCrypto $symmetricCrypto;
    private HaliteAsymmetricCrypto $asymmetricCrypto;

    public function __construct(
        AdapterBasedKeyProviderInterface $adapterBasedKeyProvider
    ) {
        $this->name = self::ADAPTER_NAME;
        $this->version = self::CURRENT_VERSION;

        parent::__construct($adapterBasedKeyProvider);

        // Initialize service dependencies
        $this->initializeServices();
    }

    public function getRequiredEncryptionKeyType(): string
    {
        return HaliteKeyFactoryAdapter::HALITE_KEY;
    }

    /**
     * Checksum operation with proper validation.
     */
    public function checksum(EncryptionRequestInterface $request): string
    {
        // Validate request - keys are optional for checksum
        $this->validateChecksumRequest($request);

        return $this->executeOperation(function () use ($request) {
            $encoding = $this->configProcessor->processEncoding($request);

            // Try to find authentication key (optional)
            $haliteKey = null;
            if ($request->hasKeys()) {
                try {
                    $key = $this->findKeyByType(
                        $request->getKeys(),
                        [
                            KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY,
                            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
                        ]
                    );
                    $haliteKey = $this->keyResolver->convertToHaliteKey($key);
                } catch (UnableToEncryptMessageException) {
                    // No appropriate key found, use keyless checksum
                    $haliteKey = null;
                }
            }

            // Process input file
            $input = $this->fileHandler->processInputFile($request->getInputFile());

            // Calculate checksum
            return HaliteFile::checksum($input, $haliteKey, $encoding);
        }, 'checksum');
    }

    public function seal(EncryptionRequestInterface $request): string|int
    {
        // Validate request - requires public key
        $this->validateSealRequest($request);

        return $this->executeOperation(function () use ($request) {
            return $this->asymmetricCrypto->seal($request);
        }, 'seal');
    }

    public function sign(EncryptionRequestInterface $request): string
    {
        // Validate request - requires secret key
        $this->validateSignRequest($request);

        return $this->executeOperation(function () use ($request) {
            return $this->asymmetricCrypto->sign($request);
        }, 'sign');
    }

    public function signAndEncrypt(EncryptionRequestInterface $request): string
    {
        return $this->asymmetricCrypto->signAndEncrypt($request);
    }

    public function unseal(EncryptionRequestInterface $request): HiddenString|bool
    {
        // Validate request - requires secret key
        $this->validateUnsealRequest($request);

        return $this->executeOperation(function () use ($request) {
            return $this->asymmetricCrypto->unseal($request);
        }, 'unseal');
    }

    public function verifyAndDecrypt(EncryptionRequestInterface $request): HiddenString
    {
        return $this->asymmetricCrypto->verifyAndDecrypt($request);
    }

    public function authenticate(EncryptionRequestInterface $request): string
    {
        return $this->symmetricCrypto->authenticate($request);
    }

    // Template method implementations

    protected function performSymmetricEncryption(EncryptionRequestInterface $request): string|int
    {
        return $this->symmetricCrypto->encrypt($request);
    }

    protected function performSymmetricDecryption(EncryptionRequestInterface $request): HiddenString|bool
    {
        return $this->symmetricCrypto->decrypt($request);
    }

    protected function performAsymmetricEncryption(EncryptionRequestInterface $request): string|int
    {
        return $this->asymmetricCrypto->encrypt($request);
    }

    protected function performAsymmetricDecryption(EncryptionRequestInterface $request): HiddenString|bool
    {
        return $this->asymmetricCrypto->decrypt($request);
    }

    protected function performSymmetricVerification(EncryptionRequestInterface $request): bool
    {
        return $this->symmetricCrypto->verify($request);
    }

    protected function performAsymmetricVerification(EncryptionRequestInterface $request): bool
    {
        return $this->asymmetricCrypto->verify($request);
    }

    /**
     * Initializes Halite-specific services.
     */
    private function initializeServices(): void
    {
        $keyFactoryAdapter = $this->getAdapterAppropriateKey(
            $this->getRequiredEncryptionKeyType()
        );

        $this->keyResolver = new HaliteKeyResolver(
            $keyFactoryAdapter,
            $this->getRequiredEncryptionKeyType()
        );

        $this->configProcessor = new HaliteConfigProcessor(self::CURRENT_VERSION);
        $this->fileHandler = new HaliteFileHandler();

        $this->symmetricCrypto = new HaliteSymmetricCrypto(
            $this->keyResolver,
            $this->configProcessor,
            $this->fileHandler
        );

        $this->asymmetricCrypto = new HaliteAsymmetricCrypto(
            $this->keyResolver,
            $this->configProcessor,
            $this->fileHandler
        );
    }
}
