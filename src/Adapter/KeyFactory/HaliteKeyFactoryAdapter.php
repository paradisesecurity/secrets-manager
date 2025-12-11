<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory;

use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\Halite\HaliteKeyConverter;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\Halite\HaliteKeyGenerator;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\Halite\HaliteKeyPairSplitter;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToGenerateKeyException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\Halite\Halite;

use function is_null;

/**
 * Key factory adapter for Halite cryptography library.
 * 
 * Handles key generation, conversion, and manipulation using
 * the Halite encryption library built on libsodium.
 * 
 * Supports:
 * - Symmetric encryption/authentication keys
 * - Asymmetric encryption/signature key pairs
 * - Key derivation from passwords
 * - Key format conversions
 */
final class HaliteKeyFactoryAdapter extends AbstractKeyFactoryAdapter
{
    public const ADAPTER_NAME = 'halite';
    public const CURRENT_VERSION = Halite::VERSION;
    public const HALITE_KEY = 'halite_key';

    public const SUPPORTED_KEY_TYPES = [
        self::HALITE_KEY,
        KeyFactoryInterface::HEX_KEY,
        KeyFactoryInterface::RAW_KEY,
    ];

    private HaliteKeyConverter $keyConverter;
    private HaliteKeyGenerator $keyGenerator;
    private HaliteKeyPairSplitter $keyPairSplitter;

    public function __construct(string $version = self::CURRENT_VERSION)
    {
        $this->name = self::ADAPTER_NAME;
        $this->supported = self::SUPPORTED_KEY_TYPES;
        $this->version = $version;

        parent::__construct();

        // Initialize service dependencies
        $this->initializeServices();
    }

    public function getAdapterSpecificKeyType(KeyInterface $key): string
    {
        return self::HALITE_KEY;
    }

    public function getAdapterRequiredKey(KeyInterface $key, string $type): mixed
    {
        return match ($type) {
            KeyFactoryInterface::HEX_KEY => $this->getHexKey($key),
            KeyFactoryInterface::RAW_KEY => $this->keyConverter->toRawKey($key),
            self::HALITE_KEY => $this->keyConverter->toHaliteKey($key),
            default => throw new UnableToLoadKeyException(
                "Unsupported key type: {$type}"
            ),
        };
    }

    public function splitKeyPair(KeyInterface $key, string $keyType): array
    {
        if (!$this->isKeyPair($key->getType())) {
            throw new UnableToLoadKeyException(
                "Key is not a key pair: {$key->getType()}"
            );
        }

        $haliteKeyPair = $this->keyConverter->toHaliteKey($key);
        return $this->keyPairSplitter->split($key, $haliteKeyPair);
    }

    public function getDefaultConfig(?string $version = null): array
    {
        return $this->keyGenerator->getDefaultConfig();
    }

    public function generateKey(KeyConfigInterface $config): KeyInterface
    {
        $type = $config->getType();
        $processedConfig = $this->processConfig($config);

        try {
            $haliteKey = $this->keyGenerator->generate($type, $processedConfig);
            
            $version = $config->getVersion() ?? $this->getVersion();
            
            return $this->createKeyFromHaliteKey($haliteKey, $type, $version);
        } catch (\Exception $exception) {
            throw new UnableToGenerateKeyException(
                "Failed to generate key of type '{$type}': {$exception->getMessage()}",
                $exception
            );
        }
    }

    /**
     * Creates a KeyInterface from Halite key.
     */
    private function createKeyFromHaliteKey(mixed $haliteKey, string $type, string $version): KeyInterface
    {
        $hex = $this->keyConverter->fromHaliteKey($haliteKey);
        return new Key($hex, $type, $this->getName(), $version);
    }

    /**
     * Processes configuration for key generation.
     */
    private function processConfig(KeyConfigInterface $config): array
    {
        $version = $config->getVersion();
        if (is_null($version)) {
            $version = $this->getVersion();
            $config->setVersion($version);
        }

        $defaultConfig = $this->getDefaultConfig($version);
        $customConfig = $config->getConfiguration();

        return $this->replaceDefaultConfigValues($defaultConfig, $customConfig);
    }

    /**
     * Initializes service dependencies.
     */
    private function initializeServices(): void
    {
        $this->keyConverter = new HaliteKeyConverter();
        $this->keyGenerator = new HaliteKeyGenerator();
        $this->keyPairSplitter = new HaliteKeyPairSplitter(
            $this->keyConverter,
            $this->getName()
        );
    }
}
