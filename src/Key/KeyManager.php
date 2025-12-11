<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\InvalidAuthenticationKeyException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToAccessKeyringException;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyringNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParagonIE\HiddenString\HiddenString;

use ParadiseSecurity\Component\SecretsManager\Key\Encryption\KeyringEncryption;
use ParadiseSecurity\Component\SecretsManager\Key\Integrity\KeyringIntegrityVerifier;
use ParadiseSecurity\Component\SecretsManager\Key\IO\KeyringIO;
use ParadiseSecurity\Component\SecretsManager\Key\Serialization\KeyringSerializer;

use function is_null;

final class KeyManager implements KeyManagerInterface
{
    private KeyringInterface|null $keyring = null;

    public function __construct(
        private MasterKeyProviderInterface $masterKeyProvider,
        private EncryptionAdapterInterface $encryptionAdapter,
        private KeyFactoryInterface $keyFactory,
        private KeyringEncryption $keyringEncryption,
        private KeyringIntegrityVerifier $integrityVerifier,
        private KeyringSerializer $keyringSerializer,
        private KeyringIO $keyringIO,
        private string $keyringName = KeyManagerInterface::KEYRING_NAME,
    ) { }

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

    public function generateKey(KeyConfigInterface $config, ?string $adapter = null): ?KeyInterface
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
            $mac = $this->keyringEncryption->generateMAC($authKey, $this->keyring->getUniqueId());
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

    public function newKeyring(?KeyInterface $authKey = null): ?KeyInterface
    {
        $this->keyring = new Keyring();

        if (!is_null($authKey)) {
            return $this->addAuth($authKey);
        }

        return $this->newAuth();
    }

    public function lockKeyring(KeyInterface $authKey): void
    {
        if ($this->keyring->isLocked()) {
            return;
        }

        $mac = $this->keyringEncryption->generateMAC($authKey, $this->keyring->getUniqueId());

        if (!$this->keyringEncryption->verifyMAC($authKey, $mac, $this->keyring->getUniqueId())) {
            throw new InvalidAuthenticationKeyException('Invalid authentication key for this keyring.');
        }

        $this->keyring->lock($mac);

    }

    public function unlockKeyring(KeyInterface $authKey): void
    {
        if (!$this->keyring->isLocked()) {
            return;
        }

        $mac = $this->keyringEncryption->generateMAC($authKey, $this->keyring->getUniqueId());

        if (!$this->keyringEncryption->verifyMAC($authKey, $mac, $this->keyring->getUniqueId())) {
            throw new InvalidAuthenticationKeyException('Invalid authentication key for this keyring.');
        }

        $this->keyring->unlock($mac);
    }

    public function doesKeyringExist(): bool
    {
        return $this->keyringIO->keyringExists();
    }

    /**
     * Loads and verifies the keyring from storage.
     *
     * This method performs the following steps:
     * 1. Validates that no keyring is already loaded
     * 2. Validates the authentication key type
     * 3. Verifies the keyring file exists
     * 4. Sets the authentication key
     * 5. Retrieves master encryption and signature keys
     * 6. Verifies file integrity (checksum and signature)
     * 7. Decrypts the keyring data
     * 8. Deserializes the keyring into a Keyring object
     * 9. Verifies the keyring's internal MAC with the auth key
     *
     * @param KeyInterface $authKey The authentication key used to verify keyring ownership
     * @throws KeyringAlreadyLoadedException If a keyring is already loaded
     * @throws InvalidAuthenticationKeyException If the auth key is invalid or wrong type
     * @throws KeyringNotFoundException If the keyring file doesn't exist
     * @throws KeyringIntegrityException If checksum or signature verification fails
     */
    public function loadKeyring(KeyInterface $authKey): void
    {
        // Step 1: Check if keyring is already loaded
        if ($this->keyring instanceof KeyringInterface) {
            throw new KeyringAlreadyLoadedException('The keyring is already loaded.');
        }

        // Step 2: Validate authentication key type
        if ($authKey->getType() !== KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY) {
            throw new InvalidAuthenticationKeyException('The provided authentication key is not a symmetric authentication key.');
        }

        // Step 3: Verify keyring file exists
        if (!$this->keyringIO->keyringExists()) {
            throw new KeyringNotFoundException(sprintf('The keyring "%s" does not exist. You must create it first.', $this->keyringName));
        }

        // Step 4: Set the authentication key for this session
        //$this->authKey = $authKey; Is this needed?

        // Step 5: Retrieve master keys (encryption key and signature public key)
        $encryptionKey = $this->masterKeyProvider->getEncryptionKey();
        $signaturePublicKey = $this->masterKeyProvider->getSignaturePublicKey();
        $signaturePublicKey = $this->checkSignatureKeyPair($signaturePublicKey);

        // Step 6: Verify file integrity (checksum and signature)
        $keyringStream = $this->keyringIO->openKeyringForReading();
        try {
            // Read the checksum file contents
            $checksumContents = $this->keyringIO->readChecksumData();

            // Parse the stored checksum and signature from the checksum file
            $storedChecksum = $this->integrityVerifier->parseChecksumFile($checksumContents);

            // Calculate the actual checksum of the keyring file
            $calculatedChecksum = $this->integrityVerifier->generateChecksum($keyringStream);

            // Verify the checksum matches (file hasn't been corrupted)
            if (!$this->integrityVerifier->verifyChecksum($calculatedChecksum, $storedChecksum)) {
                throw new KeyringIntegrityException('Keyring checksum verification failed. The file may be corrupt.');
            }

            // Verify the signature (file hasn't been tampered with)
            if (!$this->integrityVerifier->verifySignature($keyringStream, $storedChecksum, $signaturePublicKey)) {
                throw new KeyringIntegrityException('Keyring signature verification failed. The file may have been tampered with.');
            }
        } finally {
            // Always close the stream, even if an exception occurred
            if (is_resource($keyringStream)) {
                fclose($keyringStream);
            }
        }

        // Step 7: Decrypt the keyring data
        $encryptedData = $this->keyringIO->readKeyringData();
        $decryptedJson = $this->keyringEncryption->decrypt($encryptedData, $encryptionKey);

        // Step 8: Deserialize JSON into a Keyring object
        $keyring = $this->keyringSerializer->deserialize($decryptedJson);

        // Step 9: Verify the keyring's internal MAC with the authentication key
        // This ensures the authentication key matches the one used to create the keyring
        $mac = $this->keyringEncryption->generateMAC($authKey, $keyring->getUniqueId());

        // Each Encryption Adapter might have a unique way of verifying MAC
        if (!$this->keyringEncryption->verifyMAC($authKey, $mac, $keyring->getUniqueId())) {
            throw new InvalidAuthenticationKeyException('Invalid authentication key for this keyring.');
        }

        // MAC must be in the list of authorized MACs on the keyring
        // This allows revoking access to MACs
        if ($keyring->hasAccess($mac)) {
            $this->keyring = $keyring;
        }
    }

    /**
     * Saves the keyring to storage with encryption and integrity protection.
     *
     * This method performs the following steps:
     * 1. Locks the keyring if it's not already locked
     * 2. Serializes the keyring to JSON
     * 3. Encrypts the serialized data
     * 4. Writes the encrypted data to disk
     * 5. Generates and saves checksum and signature for integrity verification
     *
     * @param KeyInterface $authKey The authentication key used to lock the keyring
     * @throws UnableToAccessKeyringException If encryption or file operations fail
     * @throws UnableToSecureKeyringException If checksum/signature generation fails
     */
    public function saveKeyring(KeyInterface $authKey): void
    {
        // Step 1: Lock the keyring if it's not already locked
        if ($this->keyring->isLocked() === false) {
            $this->lockKeyring($authKey);
        }

        // Step 2: Serialize the keyring to JSON
        $serializedData = $this->keyringSerializer->serialize($this->keyring);

        // Step 3: Encrypt the serialized data
        $encryptionKey = $this->masterKeyProvider->getEncryptionKey();
        $encryptedData = $this->keyringEncryption->encrypt($serializedData, $encryptionKey);

        // Step 4: Write the encrypted data to the keyring file
        $this->keyringIO->writeKeyringData($encryptedData);

        // Step 5: Generate checksum and signature for integrity verification
        $keyringStream = $this->keyringIO->openKeyringForReading();
        try {
            // Generate checksum of the encrypted keyring file
            $checksum = $this->integrityVerifier->generateChecksum($keyringStream);

            // Generate signature using the master signature key
            $signatureSecretKey = $this->masterKeyProvider->getSignatureSecretKey();
            $signatureSecretKey = $this->checkSignatureKeyPair($signatureSecretKey);
            $signature = $this->integrityVerifier->generateSignature($keyringStream, $signatureSecretKey);

            // Combine checksum and signature into the checksum file format
            $checksumFileContent = $this->integrityVerifier->createChecksumFile($checksum, $signature);

            // Write the checksum file
            $this->keyringIO->writeChecksumData($checksumFileContent);
        } finally {
            // Always close the stream, even if an exception occurred
            if (is_resource($keyringStream)) {
                fclose($keyringStream);
            }
        }
    }

    private function checkSignatureKeyPair(?KeyInterface $key): ?KeyInterface
    {
        if (!$this->masterKeyProvider->hasSignatureKeyPair()) {
            return $key;
        }

        $keyPair = $this->masterKeyProvider->getSignatureKeyPair();

        if (is_null($key) && !is_null($keyPair)) {
            return $keyPair;
        }

        return $key;
    }

    public function rotateKeys(string $vault, array $keyNames = []): bool
    {
        // Unlock the keyring to allow modifications
        // Note: The caller should handle unlocking with appropriate auth key
        if ($this->keyring->isLocked()) {
            return false;
        }

        // If no specific keys are provided, we need to get all key names in the vault
        if (empty($keyNames)) {
            // We'll rotate the main KMS key which is used for encrypting data keys
            $keyNames = ['kms_key'];
        }

        $rotatedKeys = [];
        $oldKeys = [];

        // Generate new keys for each specified key name
        foreach ($keyNames as $keyName) {
            $oldKey = $this->keyring->getKey($vault, $keyName);
            if ($oldKey === null) {
                continue;
            }

            // Store the old key for potential rollback
            $oldKeys[$keyName] = $oldKey;

            // Generate a new key with the same configuration as the old key
            $config = new KeyConfig($oldKey->getType());
            $newKey = $this->generateKey($config, $oldKey->getAdapter());

            if ($newKey !== null) {
                $rotatedKeys[$keyName] = $newKey;
            } else {
                // If we can't generate a new key, rollback previous rotations
                foreach ($rotatedKeys as $name => $key) {
                    $this->keyring->addKey($vault, $name, $oldKeys[$name]);
                }
                return false;
            }
        }

        // Add all new keys to the keyring
        foreach ($rotatedKeys as $keyName => $newKey) {
            $this->keyring->addKey($vault, $keyName, $newKey);
        }

        return true;
    }
}
