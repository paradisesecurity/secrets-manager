<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Storage;

use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Storage\Env\EnvFileManager;
use ParadiseSecurity\Component\SecretsManager\Storage\Serialization\KeySerializer;

use function json_encode;

/**
 * Stores cryptographic keys in .env files.
 * Uses JSON serialization for structured key data storage.
 */
final class EnvironmentBasedKeyStorage implements KeyStorageInterface
{
    public const NAME = 'env';

    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
        private EnvFileManager $envFileManager,
        private KeySerializer $keySerializer,
        private string $envFileName = KeyStorageInterface::ENVIRONMENT_FILE_NAME,
    ) {
    }

    public function getName(): string
    {
        return self::NAME;
    }

    /**
     * Imports (loads) environment variables from the .env file.
     */
    public function import(string $name): mixed
    {
        // Check if already loaded
        if ($this->envFileManager->has($name)) {
            return null;
        }

        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::ENVIRONMENT
            );
            $path = $filesystem->realpath($this->envFileName);

            $this->envFileManager->load($path);
            return null;
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException(
                'Unable to import environment key file.',
                $exception
            );
        }
    }

    /**
     * Saves a key to the .env file.
     */
    public function save(string $name, KeyInterface $key): void
    {
        // Serialize key to JSON
        $serializedKey = $this->keySerializer->serializeToJson($key);

        // Load existing environment variables
        $existingEnv = $this->loadExistingEnv();

        // Merge with new key
        $newEnvContent = $this->envFileManager->merge($existingEnv, $name, $serializedKey);

        // Write to filesystem
        $this->writeEnvFile($newEnvContent);
    }

    /**
     * Resolves an environment variable name into a Key object.
     */
    public function resolve(string $name): KeyInterface
    {
        $value = $this->envFileManager->get($name);

        if ($value === null) {
            throw new UnableToLoadKeyException(
                "Environment variable '{$name}' not found."
            );
        }

        try {
            // Normalize to array format
            $data = $this->keySerializer->normalizeToArray($value);
            
            // Deserialize from JSON
            return $this->keySerializer->deserializeFromJson(json_encode($data));
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException(
                "Unable to resolve environment variable '{$name}' into key.",
                $exception
            );
        }
    }

    /**
     * Loads existing environment variables from the .env file.
     */
    private function loadExistingEnv(): array
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::ENVIRONMENT,
                $this->envFileName
            );
            
            $content = $filesystem->read($this->envFileName);
            return $this->envFileManager->parse($content);
        } catch (FilesystemNotFoundException) {
            // File doesn't exist yet, return empty array
            return [];
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException(
                'Unable to load previous environment file.',
                $exception
            );
        }
    }

    /**
     * Writes environment content to the .env file.
     */
    private function writeEnvFile(string $content): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::ENVIRONMENT
            );
            
            $filesystem->save($this->envFileName, $content);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToLoadKeyException(
                'Unable to save environment file.',
                $exception
            );
        }
    }
}
