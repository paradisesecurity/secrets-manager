<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite;

use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParagonIE\Halite\Config as HaliteConfig;
use ParagonIE\Halite\Halite;

use function is_bool;
use function is_null;
use function is_string;

/**
 * Processes and normalizes Halite-specific configuration.
 */
final class HaliteConfigProcessor
{
    public const SYMMETRIC_CONFIG = 'symmetric_config';
    public const ASYMMETRIC_CONFIG = 'asymmetric_config';

    public function __construct(
        private string $defaultVersion = Halite::VERSION,
    ) {
    }

    /**
     * Processes encoding configuration from request.
     */
    public function processEncoding(EncryptionRequestInterface $request): string|bool
    {
        $defaultEncoding = Halite::ENCODE_BASE64URLSAFE;

        $encoding = $request->getEncoding();
        if (is_string($encoding)) {
            return $encoding;
        }

        $chooseEncoder = $request->chooseEncoder();
        if (is_bool($chooseEncoder)) {
            return $chooseEncoder;
        }

        return $defaultEncoding;
    }

    /**
     * Processes Halite configuration from request.
     */
    public function processConfig(EncryptionRequestInterface $request): array
    {
        $version = $request->getVersion();
        if (is_null($version)) {
            $version = $this->defaultVersion;
            $request->setVersion($version);
        }

        $defaultConfig = $this->getVersionedConfig($version);
        $customConfig = $request->getConfiguration();

        return array_replace_recursive($defaultConfig, $customConfig);
    }

    /**
     * Extracts symmetric config from processed configuration.
     */
    public function extractSymmetricConfig(array $config): ?HaliteConfig
    {
        return $this->extractHaliteConfig($config, self::SYMMETRIC_CONFIG);
    }

    /**
     * Extracts asymmetric config from processed configuration.
     */
    public function extractAsymmetricConfig(array $config): ?HaliteConfig
    {
        return $this->extractHaliteConfig($config, self::ASYMMETRIC_CONFIG);
    }

    /**
     * Gets versioned default configuration.
     */
    private function getVersionedConfig(string $version): array
    {
        return [
            self::SYMMETRIC_CONFIG => null,
            self::ASYMMETRIC_CONFIG => null,
        ];
    }

    /**
     * Extracts Halite config from array.
     */
    private function extractHaliteConfig(array $config, string $key): ?HaliteConfig
    {
        if (!isset($config[$key])) {
            return null;
        }

        $haliteConfig = $config[$key];
        return $haliteConfig instanceof HaliteConfig ? $haliteConfig : null;
    }
}
