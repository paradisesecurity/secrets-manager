<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key\IO;

use ParadiseSecurity\Component\SecretsManager\Exception\KeyringIOException;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;

/**
 * Handles all keyring file read/write operations.
 * Extracts complexity from KeyManager.
 */
final class KeyringIO
{
    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
        private string $keyringName,
    ) {
    }

    public function keyringExists(): bool
    {
        try {
            $adapter = $this->getKeyringFilesystem();
        } catch (FilesystemNotFoundException) {
            return false;
        }

        return ($adapter instanceof FilesystemAdapterInterface);
    }

    public function readKeyringData(): string
    {
        $filesystem = $this->getKeyringFilesystem();
        
        try {
            return $filesystem->read($this->getKeyringPath());
        } catch (FilesystemErrorException $exception) {
            throw new KeyringIOException(
                "Failed to read keyring '{$this->keyringName}': {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Writes encrypted keyring data to the keyring file.
     *
     * @param string $encryptedData The encrypted keyring data
     * @throws KeyringIOException If writing fails
     */
    public function writeKeyringData(string $encryptedData): void
    {
        $filesystem = $this->getKeyringFilesystem(createIfMissing: true);
        
        try {
            $filesystem->save($this->getKeyringPath(), $encryptedData);
        } catch (FilesystemErrorException $exception) {
            throw new KeyringIOException(
                "Failed to write keyring '{$this->keyringName}': {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    public function readChecksumData(): string
    {
        $filesystem = $this->getChecksumFilesystem();
        
        try {
            return $filesystem->read($this->getChecksumPath());
        } catch (FilesystemErrorException $exception) {
            throw new KeyringIOException(
                "Failed to read checksum for '{$this->keyringName}': {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Writes checksum and signature data to the checksum file.
     *
     * @param string $checksumData The formatted checksum file content
     * @throws KeyringIOException If writing fails
     */
    public function writeChecksumData(string $checksumData): void
    {
        $filesystem = $this->getChecksumFilesystem(createIfMissing: true);
        
        try {
            $filesystem->save($this->getChecksumPath(), $checksumData);
        } catch (FilesystemErrorException $exception) {
            throw new KeyringIOException(
                "Failed to write checksum for '{$this->keyringName}': {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    public function openKeyringForReading(): mixed
    {
        $filesystem = $this->getKeyringFilesystem();
        
        try {
            return $filesystem->open($this->getKeyringPath());
        } catch (FilesystemErrorException $exception) {
            throw new KeyringIOException(
                "Failed to open keyring '{$this->keyringName}' for reading: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    private function getKeyringFilesystem(bool $createIfMissing = false): FilesystemAdapterInterface
    {
        $name = FilesystemManagerInterface::KEYRING;
        
        if ($createIfMissing) {
            return $this->filesystemManager->getFilesystem($name);
        }
        
        return $this->filesystemManager->getFilesystem($name, $this->getKeyringPath());
    }

    private function getChecksumFilesystem(bool $createIfMissing = false): FilesystemAdapterInterface
    {
        $name = FilesystemManagerInterface::CHECKSUM;
        
        if ($createIfMissing) {
            return $this->filesystemManager->getFilesystem($name);
        }
        
        return $this->filesystemManager->getFilesystem($name, $this->getChecksumPath());
    }

    private function getKeyringPath(): string
    {
        return $this->filesystemManager->getPath(
            $this->keyringName . KeyManagerInterface::KEYRING_EXTENSION
        );
    }

    private function getChecksumPath(): string
    {
        return $this->filesystemManager->getPath(
            $this->keyringName . KeyManagerInterface::CHECKSUM_EXTENSION
        );
    }
}
