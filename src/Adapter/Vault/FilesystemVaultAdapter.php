<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\Secret;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;

use function array_key_exists;
use function is_null;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;

/**
 * Filesystem-based vault adapter.
 * 
 * Stores secrets in JSON files on the filesystem. Each vault is a separate
 * JSON file containing all secrets for that vault.
 * 
 * File format:
 * ```
 * {
 *   "secret-id-1": {"uniqueId": "...", "key": "...", "value": "...", ...},
 *   "secret-id-2": {"uniqueId": "...", "key": "...", "value": "...", ...}
 * }
 * ```
 * 
 * Features:
 * - Human-readable JSON format with pretty printing
 * - Atomic writes (entire file rewritten on update)
 * - Directory and file creation on demand
 * - Configurable file extension
 */
class FilesystemVaultAdapter extends AbstractVaultAdapter
{
    public const FILE_EXTENSION = '.vault';

    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
        private string $fileExtension = self::FILE_EXTENSION,
    ) {
    }

    public function getSecret(string $key, array $options = []): SecretInterface
    {
        $path = $this->getPath($options);
        $secrets = $this->loadSecrets($path);

        if (!array_key_exists($key, $secrets)) {
            throw SecretNotFoundException::withKey($key);
        }

        return $this->deserializeSecret($secrets[$key]);
    }

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        $path = $this->getPath($options);
        $secrets = $this->loadSecrets($path);
        
        $secrets = $this->updateSecretInArray($secret, $secrets);
        $this->saveSecrets($secrets, $path);

        return $secret;
    }

    public function deleteSecretByKey(string $key, array $options): void
    {
        $path = $this->getPath($options);
        $secrets = $this->loadSecrets($path);

        if (array_key_exists($key, $secrets)) {
            unset($secrets[$key]);
            $this->saveSecrets($secrets, $path);
        }
    }

    public function deleteSecret(SecretInterface $secret, array $options = []): void
    {
        $this->deleteSecretByKey($secret->getUniqueId(), $options);
    }

    public function deleteVault(array $options = []): void
    {
        if ($options['delete_vault'] !== true) {
            return;
        }

        $path = $this->getPath($options);
        $this->eraseVault($path);
    }

    public function configureSharedOptions(OptionsResolver $resolver): void
    {
        parent::configureSharedOptions($resolver);

        $resolver->define('path')
            ->allowedTypes('string')
            ->info('Custom path to the vault file (overrides default based on vault name)');
    }

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureDeleteSecretOptions($resolver);

        $resolver->define('delete_vault')
            ->allowedTypes('bool')
            ->default(function (Options $options): bool {
                return $options['delete_all'] === true;
            })
            ->info('Delete the entire vault file (not just the secret)');
    }

    /**
     * Resolves the full path to the vault file.
     */
    private function getPath(array $options): string
    {
        $path = $options['path'] ?? $options['vault'];

        return $this->filesystemManager->getPath(
            $path . $this->fileExtension
        );
    }

    /**
     * Gets filesystem adapter, creating directories if needed.
     */
    private function getFilesystem(?string $path = null): FilesystemAdapterInterface
    {
        $name = FilesystemManagerInterface::VAULT;
        
        if (is_null($path)) {
            return $this->filesystemManager->getFilesystem($name);
        }

        return $this->filesystemManager->getFilesystem($name, $path);
    }

    /**
     * Loads secrets from vault file.
     * 
     * @return array<string, string> Map of secret ID to JSON data
     */
    private function loadSecrets(string $path): array
    {
        try {
            $adapter = $this->getFilesystem($path);
        } catch (FilesystemNotFoundException) {
            return $this->createEmptySecrets();
        }

        try {
            $contents = $adapter->read($path);
            return json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new SecretNotFoundException(
                "Invalid JSON in vault file: {$path}",
                $exception
            );
        } catch (\Exception $exception) {
            throw new SecretNotFoundException(
                "Unable to read vault file: {$path}",
                $exception
            );
        }
    }

    /**
     * Creates empty secrets array and ensures directory exists.
     */
    private function createEmptySecrets(): array
    {
        try {
            $this->getFilesystem();
        } catch (FilesystemNotFoundException $exception) {
            throw new SecretNotFoundException(
                'Vault directory does not exist and could not be created.',
                $exception
            );
        }

        return [];
    }

    /**
     * Updates a secret in the secrets array.
     */
    private function updateSecretInArray(SecretInterface $secret, array $secrets): array
    {
        $index = $secret->getUniqueId();

        if ($secret->isEncrypted()) {
            $secrets[$index] = json_encode($secret, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        }

        return $secrets;
    }

    /**
     * Saves secrets array to vault file.
     */
    private function saveSecrets(array $secrets, string $path): void
    {
        try {
            $json = json_encode($secrets, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            $adapter = $this->getFilesystem();
            $adapter->save($path, $json);
        } catch (\JsonException $exception) {
            throw new FilesystemErrorException(
                'Failed to encode secrets as JSON.',
                $exception
            );
        } catch (\Exception $exception) {
            throw new FilesystemErrorException(
                "Unable to save vault file: {$path}",
                $exception
            );
        }
    }

    /**
     * Deletes the entire vault file.
     */
    private function eraseVault(string $path): void
    {
        try {
            $adapter = $this->getFilesystem($path);
            $adapter->delete($path);
        } catch (\Exception $exception) {
            throw new FilesystemErrorException(
                "Unable to delete vault file: {$path}",
                $exception
            );
        }
    }

    /**
     * Deserializes JSON data to Secret object.
     */
    private function deserializeSecret(string $json): SecretInterface
    {
        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

            return new Secret(
                $data['uniqueId'],
                $data['key'],
                $data['value'],
                $data['encrypted'],
                $data['metadata'] ?? []
            );
        } catch (\JsonException $exception) {
            throw new SecretNotFoundException(
                'Invalid secret JSON data.',
                $exception
            );
        }
    }
}
