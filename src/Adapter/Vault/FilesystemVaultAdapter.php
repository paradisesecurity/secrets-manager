<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\Secret;

use function array_key_exists;
use function is_null;
use function json_decode;
use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;

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

        $secret = null;
        if (array_key_exists($key, $secrets)) {
            $data = json_decode($secrets[$key], true);
            $secret = new Secret(
                $data['uniqueId'],
                $data['key'],
                $data['value'],
                $data['encrypted'],
                $data['metadata']
            );
        }

        if ($secret instanceof SecretInterface) {
            return $secret;
        }

        throw SecretNotFoundException::withKey($key);
    }

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        $path = $this->getPath($options);
        $secrets = $this->updateValue($secret, $this->loadSecrets($path));
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
        $path = $this->getPath($options);

        if ($options['delete_vault'] === true) {
            $this->eraseVault($path);
        }
    }

    public function configureSharedOptions(OptionsResolver $resolver): void
    {
        parent::configureSharedOptions($resolver);

        $resolver->define('path')
            ->allowedTypes('string')
            ->info('The path to the vault filename');
    }

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureDeleteSecretOptions($resolver);

        $resolver->define('delete_vault')
            ->allowedTypes('bool')
            ->required()
            ->info('Delete the entire vault file');

        $resolver->setDefault('delete_vault', function (Options $options): bool {
            if (true === $options['delete_all']) {
                return true;
            }

            return false;
        });
    }

    private function getPath(array $options): string
    {
        $path = $options['vault'];

        if (isset($options['path'])) {
            $path = $options['path'];
        }

        return $this->filesystemManager->getPath(
            $path . $this->fileExtension
        );
    }

    private function getFilesystem(?string $path = null): FilesystemAdapterInterface
    {
        $name = FilesystemManagerInterface::VAULT;
        if (is_null($path)) {
            return $this->filesystemManager->getFilesystem($name);
        }
        return $this->filesystemManager->getFilesystem($name, $path);
    }

    private static function updateValue(SecretInterface $secret, array $secrets): array
    {
        $index = $secret->getUniqueId();

        if ($secret->isEncrypted()) {
            $secrets[$index] = json_encode($secret, JSON_PRETTY_PRINT);
        }

        return $secrets;
    }

    private function loadSecrets(string $path): array
    {
        try {
            $adapter = $this->getFilesystem($path);
        } catch (FilesystemNotFoundException $exception) {
            return $this->createSecrets();
        }

        try {
            $contents = $adapter->read($path);
            return json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $exception) {
            throw new SecretNotFoundException('Unable to read the secrets vault file.', $exception);
        }
    }

    private function createSecrets(): array
    {
        try {
            $this->getFilesystem();
        } catch (FilesystemNotFoundException $exception) {
            throw new SecretNotFoundException('Unable to access the secrets vault directory.', $exception);
        }

        return [];
    }

    private function eraseVault(string $path): void
    {
        try {
            $adapter = $this->getFilesystem($path);
            $adapter->delete($path);
        } catch (\Exception $exception) {
            throw new FilesystemErrorException('Unable to delete the secrets vault file.', $exception);
        }
    }

    private function saveSecrets(array $secrets, string $path): void
    {
        try {
            $secrets = json_encode($secrets, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            $adapter = $this->getFilesystem();
            $adapter->save($path, $secrets);
        } catch (\Exception $exception) {
            throw new FilesystemErrorException('Unable to save the secrets vault file.', $exception);
        }
    }
}
