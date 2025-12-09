<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret;

use ParadiseSecurity\Component\SecretsManager\Exception\IncorrectKeyProvidedException;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToAccessRestrictedCommandsException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfig;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use ParadiseSecurity\Component\SecretsManager\Secret\Authentication\SecretAuthentication;
use ParadiseSecurity\Component\SecretsManager\Secret\Cache\SecretCacheKeyManager;
use ParadiseSecurity\Component\SecretsManager\Secret\Encryption\SecretEncryption;
use ParadiseSecurity\Component\SecretsManager\Secret\Key\SecretKeyBuilder;
use ParadiseSecurity\Component\SecretsManager\Secret\Serialization\SecretSerializer;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\VaultAdapterInterface;

use function array_merge;

final class SecretManager implements SecretManagerInterface
{
    private KeyInterface $authKey;

    private string $vault = '';

    private array $options = [];

    public function __construct(
        private VaultAdapterInterface $adapter,
        private KeyManagerInterface $keyManager,
        private SecretEncryption $secretEncryption,
        private SecretAuthentication $secretAuthentication,
        private SecretKeyBuilder $keyBuilder,
        private SecretCacheKeyManager $cacheKeyManager,
        private SecretSerializer $serializer,
        KeyInterface $authKey,
        string $vault = '',
        array $options = []
    ) {
        $this->validateAuthKey($authKey);
        $this->authKey = $authKey;
        $this->keyManager->loadKeyring($authKey);

        if ($vault !== '') {
            $this->vault($vault);
        }
        
        if (!empty($options)) {
            $this->options($options);
        }
    }

    public function newVault(string $vault): void
    {
        $this->keyManager->unlockKeyring($this->authKey);

        if ($this->keyManager->hasVault($vault)) {
            return;
        }

        // Create KMS key for envelope encryption
        $kmsKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $this->keyManager->newKey($vault, 'kms_key', $kmsKeyConfig);

        // Create and split cache key for secret hashing
        $cacheKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);
        $cacheKey = $this->keyManager->newKey($vault, 'cache_key', $cacheKeyConfig);

        $this->storeSplitCacheKey($vault, $cacheKey);

        $this->keyManager->saveKeyring($this->authKey);
    }

    public function deleteVault(string $vault): void
    {
        $options = $this->prepareOptions([
            'delete_all' => true,
            'vault' => $vault,
        ]);

        $resolver = $this->createOptionsResolver();

        try {
            $this->adapter->deleteVault($resolver->resolve($options));
        } catch (\Exception $ignored) {
            return;
        }

        $this->keyManager->unlockKeyring($this->authKey);
        $this->keyManager->flushVault($vault);
        $this->keyManager->saveKeyring($this->authKey);
    }

    public function getSecret(string $key, array $options = []): SecretInterface
    {
        return $this->getSecret2($key, $options);
    }

    public function get(string $key): mixed
    {
        $this->ensureVaultIsSet();

        try {
            $secret = $this->getSecret($key, $this->options);
        } catch (SecretNotFoundException) {
            return null;
        }

        if (!$secret->isEncrypted()) {
            return $secret->getValue();
        }

        return $this->decryptAndDeserializeSecret($secret);
    }

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        return $this->putSecret2($secret, $options);
    }

    public function set(string $key, mixed $value): bool
    {
        $this->ensureVaultIsSet();

        try {
            $serializedValue = $this->serializer->serialize($value);
            $authenticatedValue = $this->secretAuthentication->authenticateData(
                $serializedValue,
                $this->authKey
            );

            $secret = $this->createEncryptedSecret($key, $authenticatedValue);
            $this->putSecret($secret, $this->options);
            
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    public function deleteSecretByKey(string $key, array $options = []): void
    {
        $this->deleteSecretByKey2($key, $options);
    }

    public function deleteSecret(SecretInterface $secret, array $options = []): void
    {
        $this->deleteSecret2($secret, $options);
    }

    public function delete(string $key): bool
    {
        $this->ensureVaultIsSet();

        try {
            $this->deleteSecretByKey($key, $this->options);
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    public function vault(string $vault): self
    {
        $this->vault = $vault;
        return $this;
    }

    public function options(array $options): self
    {
        $this->options = $options;
        return $this;
    }

    public function rotateSecrets(string $vault, array $secretKeys = []): bool
    {
        $originalVault = $this->vault;
        $this->vault($vault);

        try {
            $this->keyManager->unlockKeyring($this->authKey);

            if (!$this->keyManager->rotateKeys($vault, ['kms_key'])) {
                $this->vault($originalVault);
                return false;
            }

            if (empty($secretKeys)) {
                $this->keyManager->saveKeyring($this->authKey);
                $this->vault($originalVault);
                return true;
            }

            $this->reencryptSecrets($secretKeys);

            $this->keyManager->saveKeyring($this->authKey);
            $this->vault($originalVault);
            return true;
        } catch (\Exception) {
            $this->vault($originalVault);
            return false;
        }
    }

    public function getVaultAdapter(): VaultAdapterInterface
    {
        return $this->adapter;
    }

    // --- Private Helper Methods ---

    private function validateAuthKey(KeyInterface $authKey): void
    {
        if ($authKey->getType() !== KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY) {
            throw new IncorrectKeyProvidedException(
                'Authentication key must be a symmetric authentication key'
            );
        }
    }

    private function storeSplitCacheKey(string $vault, KeyInterface $cacheKey): void
    {
        $rawCacheKey = $this->keyManager->getRawKeyMaterial($cacheKey)->getString();
        $splitKeys = $this->cacheKeyManager->splitCacheKey($rawCacheKey);

        $this->keyManager->addMetadata($vault, 'cache_key_l', $splitKeys['cache_key_l']);
        $this->keyManager->addMetadata($vault, 'cache_key_r', $splitKeys['cache_key_r']);
    }

    private function decryptAndDeserializeSecret(SecretInterface $secret): mixed
    {
        try {
            // Decrypt the secret value with its data key
            $dataKey = $this->decryptSecretDataKey($secret);
            $decryptedValue = $this->secretEncryption->decryptValue(
                $secret->getValue(),
                $dataKey
            );

            // Verify and strip MAC
            $verifiedData = $this->secretAuthentication->verifyData(
                $decryptedValue,
                $this->authKey
            );

            // Deserialize JSON
            return $this->serializer->deserialize($verifiedData);
        } catch (\Exception) {
            return null;
        }
    }

    private function createEncryptedSecret(string $key, string $authenticatedValue): SecretInterface
    {
        // Generate new data encryption key (DEK)
        $dataKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $dataKey = $this->keyManager->generateKey($dataKeyConfig);

        // Encrypt the DEK with KMS key (envelope encryption)
        $kmsKey = $this->keyManager->getKey($this->vault, 'kms_key');
        $encryptedDataKey = $this->secretEncryption->encryptDataKey($dataKey, $kmsKey);

        // Encrypt the actual value with the DEK
        $encryptedValue = $this->secretEncryption->encryptValue($dataKey, $authenticatedValue);

        // Generate SHM key for efficient lookup
        $shmKey = $this->generateSHMKey($key);

        return new Secret($shmKey, $encryptedDataKey, $encryptedValue, true);
    }

    private function decryptSecretDataKey(SecretInterface $secret): KeyInterface
    {
        $kmsKey = $this->keyManager->getKey($this->vault, 'kms_key');
        $dataKeyData = $this->secretEncryption->decryptDataKey(
            $secret->getKey(),
            $kmsKey
        );

        return $this->keyBuilder->buildFromData($dataKeyData);
    }

    private function reencryptSecrets(array $secretKeys): void
    {
        foreach ($secretKeys as $secretKey) {
            try {
                $secret = $this->getSecret($secretKey);
                
                // Decrypt with old key
                $dataKey = $this->decryptSecretDataKey($secret);
                $decryptedValue = $this->secretEncryption->decryptValue(
                    $secret->getValue(),
                    $dataKey
                );

                // Strip MAC and deserialize
                $strippedValue = $this->secretAuthentication->stripMac($decryptedValue);
                $value = $this->serializer->deserialize($strippedValue);

                // Re-encrypt with new key
                $serializedValue = $this->serializer->serialize($value);
                $authenticatedValue = $this->secretAuthentication->authenticateData(
                    $serializedValue,
                    $this->authKey
                );

                $newSecret = $this->createEncryptedSecret($secretKey, $authenticatedValue);
                $this->putSecret($newSecret, $this->options);
            } catch (\Exception) {
                continue; // Skip failed secrets
            }
        }
    }

    private function generateSHMKey(string $key): string
    {
        return $this->cacheKeyManager->generateSHMKey(
            $this->vault,
            $key,
            $this->keyManager->getMetadata($this->vault, 'cache_key_l'),
            $this->keyManager->getMetadata($this->vault, 'cache_key_r')
        );
    }

    private function getSecret2(string $key, array $options = []): SecretInterface
    {
        $options = $this->prepareOptions($options);
        $shmKey = $this->generateSHMKey($key);

        $resolver = $this->createOptionsResolver();
        return $this->adapter->getSecret($shmKey, $resolver->resolve($options));
    }

    private function putSecret2(SecretInterface $secret, array $options = []): SecretInterface
    {
        $options = $this->prepareOptions($options);
        $resolver = $this->createOptionsResolver();
        
        return $this->adapter->putSecret($secret, $resolver->resolve($options));
    }

    private function deleteSecretByKey2(string $key, array $options = []): void
    {
        $secret = $this->getSecret($key, $options);
        $this->deleteSecret($secret, $options);
    }

    private function deleteSecret2(SecretInterface $secret, array $options = []): void
    {
        $options = $this->prepareOptions($options);
        $resolver = $this->createOptionsResolver();
        
        $this->adapter->deleteSecret($secret, $resolver->resolve($options));
    }

    private function prepareOptions(array $options): array
    {
        $options = array_merge($this->options, $options);

        $vault = $options['vault'] ?? $this->vault;

        if ($this->vault === '' && $vault !== '') {
            $this->vault = $vault;
        }

        $this->ensureVaultIsSet();

        $options['vault'] = $this->vault;

        return $options;
    }

    private function ensureVaultIsSet(): void
    {
        if ($this->vault === '') {
            throw new UnableToAccessRestrictedCommandsException(
                'Cannot access secrets without first calling "vault(\'vault_name\')".'
            );
        }
    }

    private function createOptionsResolver(): OptionsResolver
    {
        $resolver = new OptionsResolver();
        $this->adapter->configureSharedOptions($resolver);
        $this->adapter->configureDeleteSecretOptions($resolver);
        return $resolver;
    }
}
