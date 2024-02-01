<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\FileEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Encryption\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\InvalidSignatureOrChecksumException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToAccessKeyringException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToGenerateSignatureOrChecksumException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\File\Checksum;
use ParadiseSecurity\Component\SecretsManager\File\ChecksumInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParagonIE\HiddenString\HiddenString;

use function is_null;
use function json_decode;
use function json_encode;

use const JSON_PRETTY_PRINT;

final class KeyManager implements KeyManagerInterface
{
    private string $accessor;

    private KeyringInterface|null $keyring = null;

    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
        private MasterKeyProviderInterface $masterKeyProvider,
        private EncryptionAdapterInterface $encryptionAdapter,
        private KeyFactoryInterface $keyFactory,
        private string $keyringName = KeyManagerInterface::KEYRING_NAME
    ) {
        $this->masterKeyProvider->setAccessor($this, $this->masterKeyProvider);
    }

    public function setAccessor(MasterKeyProviderInterface $keyProvider, KeyManagerInterface $keyManager, string $accessor)
    {
        if ($keyManager === $this && $keyProvider === $this->masterKeyProvider) {
            $this->accessor = $accessor;
        }
    }

    public function flushVault(string $vault): void
    {
        $this->keyring->flushKeys($vault);
    }

    public function flushKeyring(): void
    {
        $this->keyring->flushVault();
        $this->keyring->flushAuth();
        $this->keyring = null;
    }

    public function getEncryptionAdapter(): EncryptionAdapterInterface
    {
        return $this->encryptionAdapter;
    }

    public function getKeyFactory(): KeyFactoryInterface
    {
        return $this->keyFactory;
    }

    public function hasVault(string $vault): bool
    {
        return $this->keyring->hasVault($vault);
    }

    public function generateKey(KeyConfigInterface $config, string $adapter = null): ?KeyInterface
    {
        if (is_null($adapter)) {
            $adapter = $this->encryptionAdapter->getName();
        }

        return $this->keyFactory->generateKey($config, $adapter);
    }

    public function getRawKeyMaterial(KeyInterface $key): HiddenString
    {
        return $this->keyFactory->getRawKeyMaterial($key);
    }

    public function addKey(string $vault, string $name, KeyInterface $key): void
    {
        $this->keyring->addKey($vault, $name, $key);
    }

    public function addMetadata(string $vault, string $name, mixed $value): void
    {
        $this->keyring->addMetadata($vault, $name, $value);
    }

    public function newKey(string $vault, string $name, KeyConfigInterface $config): ?KeyInterface
    {
        $key = $this->generateKey($config);

        if (!is_null($key)) {
            $this->addKey($vault, $name, $key);
        }

        return $key;
    }

    public function getKey(string $vault, string $name): ?KeyInterface
    {
        return $this->keyring->getKey($vault, $name);
    }

    public function getMetadata(string $vault, string $name): mixed
    {
        return $this->keyring->getMetadata($vault, $name);
    }

    public function addAuth(KeyInterface $authKey): KeyInterface
    {
        if ($authKey->getType() !== KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY) {
            return $authKey;
        }

        if ($this->keyring instanceof KeyringInterface) {
            $uniqueId = $this->keyring->getUniqueId();
            $mac = $this->generateMAC($authKey, $uniqueId);
            $this->keyring->addAuth($mac);
        }

        return $authKey;
    }

    public function newAuth(): ?KeyInterface
    {
        $config = new KeyConfig(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);
        $key = $this->generateKey($config);

        if (!is_null($key)) {
            $this->addAuth($key);
        }

        return $key;
    }

    public function newKeyring(KeyInterface $authKey = null): ?KeyInterface
    {
        $this->keyring = new Keyring();

        if (!is_null($authKey)) {
            return $this->addAuth($authKey);
        }

        return $this->newAuth();
    }

    private function generateMAC(KeyInterface $authKey, string $uniqueId): string
    {
        $request = new MessageEncryptionRequest(new HiddenString($uniqueId), $authKey);

        return $this->encryptionAdapter->authenticate($request);
    }

    public function lockKeyring(KeyInterface $authKey): void
    {
        if (!$this->keyring->isLocked()) {
            $uniqueId = $this->keyring->getUniqueId();
            $mac = $this->getAccessMac($authKey, $uniqueId);
            $this->keyring->lock($mac);
        }
    }

    public function unlockKeyring(KeyInterface $authKey): void
    {
        if ($this->keyring->isLocked()) {
            $uniqueId = $this->keyring->getUniqueId();
            $mac = $this->getAccessMac($authKey, $uniqueId);
            $this->keyring->unlock($mac);
        }
    }

    private function getAccessMac(KeyInterface $authKey, string $uniqueId): string
    {
        $mac = $this->generateMAC($authKey, $uniqueId);

        if ($this->verifyAccess($authKey, $mac, $uniqueId) === false) {
            return '';
        }

        return $mac;
    }

    private function verifyAccess(KeyInterface $authKey, string $mac, string $uniqueId): bool
    {
        $request = new MessageEncryptionRequest(new HiddenString($uniqueId), $authKey, [EncryptionRequestInterface::MAC => $mac]);

        return $this->encryptionAdapter->verify($request);
    }

    public function doesKeyringExist(): bool
    {
        try {
            $adapter = $this->getKeyringFilesystem();
        } catch (FilesystemNotFoundException $exception) {
            return false;
        }

        return ($adapter instanceof FilesystemAdapterInterface);
    }

    public function loadKeyring(KeyInterface $authKey): void
    {
        if (($this->keyring instanceof KeyringInterface)) {
            return;
        }

        if ($this->doesKeyringExist() === false) {
            throw new UnableToAccessKeyringException('Keyring does not exist. Note: Create a new keyring first.');
        }

        $storedChecksum = $this->readChecksum();
        $fileChecksum = new Checksum($storedChecksum);

        $filesystem = $this->getKeyringFilesystem();

        $readOnly = $this->openReadOnlyKeyring($filesystem);

        $checksum = $this->generateChecksum($readOnly);

        if (!$this->verifyChecksum($checksum, $fileChecksum)) {
            throw new InvalidSignatureOrChecksumException('Invalid checksum.');
        }

        if (!$this->verifySignature($readOnly, $fileChecksum)) {
            throw new InvalidSignatureOrChecksumException('Invalid signature.');
        }

        try {
            $encryptedData = $filesystem->read($this->getKeyringPath());
        } catch (FilesystemErrorException $exception) {
            throw new UnableToAccessKeyringException('Unable to read the contents of the keyring', $exception);
        }

        $decryptedData = $this->decryptEncryptedData($encryptedData);

        $keyring = $this->unserializeDecryptedData($decryptedData);

        if (!($keyring instanceof KeyringInterface)) {
            return;
        }

        $uniqueId = $keyring->getUniqueId();
        $mac = $this->getAccessMac($authKey, $uniqueId);
        if ($keyring->hasAccess($mac)) {
            $this->keyring = $keyring;
        }
    }

    public function saveKeyring(KeyInterface $authKey): void
    {
        if ($this->keyring->isLocked() === false) {
            $this->lockKeyring($authKey);
        }

        $serializedData = $this->serializeKeyring($this->keyring);

        $encryptedData = $this->encryptSerializedData($serializedData);

        $filesystem = $this->getKeyringFilesystem(true);

        try {
            $filesystem->save($this->getKeyringPath(), $encryptedData);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToSecureKeyringException('Unable to write the encrypted contents to the keyring.', $exception);
        }

        $readOnly = $this->openReadOnlyKeyring($filesystem);

        $checksum = $this->generateChecksum($readOnly);
        $signature = $this->generateSignature($readOnly);

        $this->saveChecksum($checksum . $signature);
    }

    private function saveChecksum(string $checksum): void
    {
        $filesystem = $this->getChecksumFilesystem(true);

        try {
            $filesystem->save($this->getChecksumPath(), $checksum);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToSecureKeyringException('Unable to save the checksum data.', $exception);
        }
    }

    private function serializeKeyring(KeyringInterface $keyring): string
    {
        return json_encode($keyring, JSON_PRETTY_PRINT);
    }

    private function unserializeDecryptedData(HiddenString $decryptedData): mixed
    {
        $serializedData = $decryptedData->getString();

        try {
            $data = json_decode($serializedData, true);
            $keyring = new Keyring();
            $keyring = $keyring->withSecuredData(
                $data['uniqueId'],
                $data['vault'],
                $data['macs']
            );
        } catch (\Exception $exception) {
            $keyring = false;
        }

        if ($keyring === false) {
            throw new UnableToAccessKeyringException('Could not unserialize the keyring.');
        }

        return $keyring;
    }

    private function encryptSerializedData(string $serializedData): string
    {
        $encryptionKey = $this->masterKeyProvider->getEncryptionKey($this->accessor);

        $request = new MessageEncryptionRequest(new HiddenString($serializedData), $encryptionKey);

        try {
            return $this->encryptionAdapter->encrypt($request);
        } catch (UnableToEncryptMessageException $exception) {
            throw new UnableToAccessKeyringException('Could not encrypt the keyring.', $exception);
        }
    }

    private function decryptEncryptedData(string $encryptedData): HiddenString
    {
        $encryptionKey = $this->masterKeyProvider->getEncryptionKey($this->accessor);

        $request = new MessageEncryptionRequest(new HiddenString($encryptedData), $encryptionKey);

        try {
            return $this->encryptionAdapter->decrypt($request);
        } catch (UnableToEncryptMessageException $exception) {
            throw new UnableToAccessKeyringException('Could not decrypt the keyring.', $exception);
        }
    }

    private function openReadOnlyKeyring(FilesystemAdapterInterface $filesystem): mixed
    {
        try {
            return $filesystem->open($this->getKeyringPath());
        } catch (FilesystemErrorException $exception) {
            throw new UnableToAccessKeyringException('Unable to open the keyring for read only access.', $exception);
        }
    }

    private function generateSignature(mixed $readOnly): string
    {
        $secretKey = $this->masterKeyProvider->getSignatureSecretKey($this->accessor);
        $secretKey = $this->checkSignatureKeyPair($secretKey);

        $config = [
            EncryptionRequestInterface::ASYMMETRIC => true,
        ];
        $request = new FileEncryptionRequest($readOnly, null, $secretKey, $config);

        try {
            return $this->encryptionAdapter->sign($request);
        } catch (UnableToEncryptMessageException $exception) {
            throw new UnableToGenerateSignatureOrChecksumException('Unable to generate signature.', $exception);
        }
    }

    private function generateChecksum(mixed $readOnly): string
    {
        $request = new FileEncryptionRequest($readOnly, null, []);

        try {
            return $this->encryptionAdapter->checksum($request);
        } catch (UnableToEncryptMessageException $exception) {
            throw new UnableToGenerateSignatureOrChecksumException('Unable to generate checksum.', $exception);
        }
    }

    private function verifyChecksum(string $checksum, ChecksumInterface $fileChecksum): bool
    {
        return ($checksum === $fileChecksum->getChecksum());
    }

    private function verifySignature(mixed $readOnly, ChecksumInterface $fileChecksum): bool
    {
        $publicKey = $this->masterKeyProvider->getSignaturePublicKey($this->accessor);
        $publicKey = $this->checkSignatureKeyPair($publicKey);

        $config = [
            EncryptionRequestInterface::ASYMMETRIC => true,
            EncryptionRequestInterface::SIGNATURE => $fileChecksum->getSignature(),
        ];
        $request = new FileEncryptionRequest($readOnly, null, [$publicKey], $config);

        return $this->encryptionAdapter->verify($request);
    }

    private function checkSignatureKeyPair(?KeyInterface $key): ?KeyInterface
    {
        if (!$this->masterKeyProvider->hasSignatureKeyPair()) {
            return $key;
        }

        $keyPair = $this->masterKeyProvider->getSignatureKeyPair($this->accessor);

        if (is_null($key) && !is_null($keyPair)) {
            return $keyPair;
        }

        return $key;
    }

    private function readChecksum(): string
    {
        $filesystem = $this->getChecksumFilesystem();

        try {
            return $filesystem->read($this->getChecksumPath());
        } catch (FilesystemErrorException $exception) {
            throw new UnableToAccessKeyringException('Checksum could not be read.', $exception);
        }
    }

    private function getKeyringFilesystem($default = false): FilesystemAdapterInterface
    {
        $name = FilesystemManagerInterface::KEYRING;
        if ($default) {
            return $this->filesystemManager->getFilesystem($name);
        }
        return $this->filesystemManager->getFilesystem($name, $this->getKeyringPath());
    }

    private function getChecksumFilesystem($default = false): FilesystemAdapterInterface
    {
        $name = FilesystemManagerInterface::CHECKSUM;
        if ($default) {
            return $this->filesystemManager->getFilesystem($name);
        }
        return $this->filesystemManager->getFilesystem($name, $this->getChecksumPath());
    }

    private function getChecksumPath(): string
    {
        return $this->filesystemManager->getPath(
            $this->keyringName . KeyManagerInterface::CHECKSUM_EXTENSION
        );
    }

    private function getKeyringPath(): string
    {
        return $this->filesystemManager->getPath(
            $this->keyringName . KeyManagerInterface::KEYRING_EXTENSION
        );
    }
}
