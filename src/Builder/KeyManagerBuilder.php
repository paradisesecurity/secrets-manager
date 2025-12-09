<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManager;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Encryption\KeyringEncryption;
use ParadiseSecurity\Component\SecretsManager\Key\Integrity\KeyringIntegrityVerifier;
use ParadiseSecurity\Component\SecretsManager\Key\Serialization\KeyringSerializer;
use ParadiseSecurity\Component\SecretsManager\Key\IO\KeyringIO;

/**
 * Sub-builder for KeyManager configuration.
 */
final class KeyManagerBuilder
{
    private ?FilesystemManagerInterface $filesystemManager = null;
    private ?MasterKeyProviderInterface $masterKeyProvider = null;
    private ?EncryptionAdapterInterface $encryptionAdapter = null;
    private ?KeyFactoryInterface $keyFactory = null;
    private string $keyringName = 'keyring';

    private function __construct()
    {
    }

    public static function create(): self
    {
        return new self();
    }

    public function withFilesystemManager(FilesystemManagerInterface $manager): self
    {
        $this->filesystemManager = $manager;
        return $this;
    }

    public function withMasterKeyProvider(MasterKeyProviderInterface $provider): self
    {
        $this->masterKeyProvider = $provider;
        return $this;
    }

    public function withEncryptionAdapter(EncryptionAdapterInterface $adapter): self
    {
        $this->encryptionAdapter = $adapter;
        return $this;
    }

    public function withKeyFactory(KeyFactoryInterface $factory): self
    {
        $this->keyFactory = $factory;
        return $this;
    }

    public function withKeyringName(string $name): self
    {
        $this->keyringName = $name;
        return $this;
    }

    public function build(): KeyManagerInterface
    {
        $keyringEncryption = new KeyringEncryption($this->encryptionAdapter);

        $integrityVerifier = new KeyringIntegrityVerifier($this->encryptionAdapter);

        $keyringSerializer = new KeyringSerializer();

        $keyringIO = new KeyringIO($this->filesystemManager, $this->keyringName);

        return new KeyManager(
            $this->masterKeyProvider,
            $this->encryptionAdapter,
            $this->keyFactory,
            $keyringEncryption,
            $integrityVerifier,
            $keyringSerializer,
            $keyringIO,
            $this->keyringName
        );
    }
}
