<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Storage;

use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Storage\Serialization\KeySerializer;

/**
 * Stores cryptographic keys in individual files.
 * Uses line-delimited format for human-readable key storage.
 */
final class FileBasedKeyStorage implements KeyStorageInterface
{
    public const NAME = 'file';

    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
        private KeySerializer $keySerializer,
        private string $keyFileExt = KeyStorageInterface::KEY_FILE_EXTENSION,
    ) {
    }

    public function getName(): string
    {
        return self::NAME;
    }

    /**
     * Imports (reads) a key file and returns its content.
     */
    public function import(string $name): ?string
    {
        $filename = $this->getFilename($name);

        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::MASTER_KEYS,
                $filename
            );
        } catch (FilesystemNotFoundException) {
            return null;
        }

        try {
            return $filesystem->read($filename);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToLoadKeyException(
                "Unable to import key file '{$filename}'.",
                $exception
            );
        }
    }

    /**
     * Saves a key to a file in line-delimited format.
     */
    public function save(string $name, KeyInterface $key): void
    {
        $filename = $this->getFilename($name);
        
        // Serialize to line-delimited format
        $content = $this->keySerializer->serializeToLines($key);

        // Write to filesystem
        $filesystem = $this->filesystemManager->getFilesystem(
            FilesystemManagerInterface::MASTER_KEYS
        );

        try {
            $filesystem->save($filename, $content);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToLoadKeyException(
                "Unable to save key file '{$filename}'.",
                $exception
            );
        }
    }

    /**
     * Resolves file content into a Key object.
     */
    public function resolve(string $content): KeyInterface
    {
        try {
            return $this->keySerializer->deserializeFromLines($content);
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException(
                'Unable to resolve file content into key.',
                $exception
            );
        }
    }

    /**
     * Generates the full filename with extension.
     */
    private function getFilename(string $name): string
    {
        // Remove extension if already present
        if (str_ends_with($name, $this->keyFileExt)) {
            return $this->filesystemManager->getPath($name);
        }

        return $this->filesystemManager->getPath($name . $this->keyFileExt);
    }
}
