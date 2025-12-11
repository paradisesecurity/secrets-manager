<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Provider;

use ParadiseSecurity\Component\SecretsManager\Exception\MasterKeyException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Loader\DelegatingKeyLoaderInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Provides master keys loaded from secure storage.
 * 
 * Master keys are the root of trust in the secrets management system.
 * This provider:
 * 1. Loads keys from configured storage (files, environment, etc.)
 * 2. Validates that all required keys are present
 * 3. Provides type-safe access to individual keys
 * 4. (Future) Applies security policies and access controls
 * 
 * Security model:
 * - Keys are loaded once on construction
 * - Keys are held in memory for application lifetime
 * - Future: Add access logging, rate limiting, permission checks
 * 
 * Usage:
 * ```
 * $config = MasterKeyConfiguration::forLoader('file');
 * $provider = new MasterKeyProvider($keyLoader, $config);
 * 
 * $encryptionKey = $provider->getEncryptionKey();
 * $signatureKey = $provider->getSignatureSecretKey();
 * ```
 */
final class MasterKeyProvider implements MasterKeyProviderInterface
{
    private MasterKeyCollection $keys;

    /**
     * @param DelegatingKeyLoaderInterface $delegatingKeyLoader Key loader registry
     * @param MasterKeyConfiguration $config Loading configuration
     * @param LoggerInterface|null $logger Logger for audit trail
     */
    public function __construct(
        private DelegatingKeyLoaderInterface $delegatingKeyLoader,
        private MasterKeyConfiguration $config,
        private ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
        $this->keys = new MasterKeyCollection();
        
        $this->loadMasterKeys();
    }

    public function getKeys(): array
    {
        return $this->keys->toArray();
    }

    public function getEncryptionKey(): KeyInterface
    {
        $this->logger->debug('Accessing master encryption key');
        return $this->keys->getEncryptionKey();
    }

    public function hasSignatureKeyPair(): bool
    {
        return $this->keys->hasSignatureKeyPair();
    }

    public function getSignatureKeyPair(): KeyInterface
    {
        $this->logger->debug('Accessing master signature key pair');
        return $this->keys->getSignatureKeyPair();
    }

    public function getSignatureSecretKey(): KeyInterface
    {
        $this->logger->debug('Accessing master signature secret key');
        return $this->keys->getSignatureSecretKey();
    }

    public function getSignaturePublicKey(): KeyInterface
    {
        $this->logger->debug('Accessing master signature public key');
        return $this->keys->getSignaturePublicKey();
    }

    public function isComplete(): bool
    {
        try {
            $this->keys->validate();
            return true;
        } catch (MasterKeyException) {
            return false;
        }
    }

    public function getMissingKeys(): array
    {
        return $this->keys->getMissingKeys();
    }

    /**
     * Loads master keys from configured storage.
     * 
     * @throws MasterKeyException If loading fails or keys are incomplete
     */
    private function loadMasterKeys(): void
    {
        $loaderName = $this->config->getLoaderName();
        $this->logger->info("Loading master keys from loader: {$loaderName}");

        try {
            $loader = $this->delegatingKeyLoader->getLoader($loaderName);
        } catch (\Exception $exception) {
            throw MasterKeyException::loaderFailed($loaderName, $exception);
        }

        $loadedCount = 0;
        $failedKeys = [];

        foreach ($this->config->getRequiredKeys() as $keyName) {
            try {
                $this->logger->debug("Loading master key: {$keyName}");
                
                // Import key contents from storage
                $contents = $loader->import($keyName);
                
                // If import returns null, use key name as fallback
                $contents = $contents ?? $keyName;
                
                // Resolve contents to Key object
                $key = $loader->resolve($contents);
                
                // Add to collection
                $this->keys->addKey($key);
                $loadedCount++;
                
                $this->logger->debug("Successfully loaded master key: {$keyName}");
                
            } catch (UnableToLoadKeyException $exception) {
                $failedKeys[] = $keyName;
                $this->logger->warning(
                    "Failed to load master key: {$keyName}",
                    ['error' => $exception->getMessage()]
                );
            }
        }

        $this->logger->info("Loaded {$loadedCount} master keys");

        // Validate that all required keys are present
        try {
            $this->keys->validate();
        } catch (MasterKeyException $exception) {
            $missing = $this->keys->getMissingKeys();
            $this->logger->error(
                'Master key validation failed',
                ['missing_keys' => $missing, 'failed_keys' => $failedKeys]
            );
            throw $exception;
        }
    }

    /**
     * Creates provider with default configuration.
     * 
     * @param DelegatingKeyLoaderInterface $loader Key loader
     * @param string $loaderName Loader name (default: 'file')
     * @param LoggerInterface|null $logger Optional logger
     */
    public static function createDefault(
        DelegatingKeyLoaderInterface $loader,
        string $loaderName = 'file',
        ?LoggerInterface $logger = null
    ): self {
        $config = MasterKeyConfiguration::forLoader($loaderName);
        return new self($loader, $config, $logger);
    }
}
