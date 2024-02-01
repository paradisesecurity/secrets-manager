<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret;

use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\IncorrectKeyProvidedException;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToAccessRestrictedCommandsException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfig;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\HiddenString\HiddenString;
use Symfony\Component\OptionsResolver\OptionsResolver;

use function array_merge;
use function json_decode;
use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use const SODIUM_CRYPTO_SHORTHASH_KEYBYTES;

final class SecretManager implements SecretManagerInterface
{
    private KeyInterface $authKey;

    private string $vault = '';

    private array $options = [];

    public function __construct(
        private VaultAdapterInterface $adapter,
        private KeyManagerInterface $keyManager,
        KeyInterface $authKey,
        string $vault = '',
        array $options = [],
    ) {
        if ($authKey->getType() !== KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY) {
            throw new IncorrectKeyProvidedException();
        }
        $this->authKey = $authKey;

        $this->keyManager->loadKeyring($authKey);
    }

    public function newVault(string $vault): void
    {
        $this->keyManager->unlockKeyring($this->authKey);

        if ($this->keyManager->hasVault($vault)) {
            return;
        }

        $kmsKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $this->keyManager->newKey($vault, 'kms_key', $kmsKeyConfig);

        $cacheKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);
        $cacheKey = $this->keyManager->newKey($vault, 'cache_key', $cacheKeyConfig);
        $rawCacheKey = $this->keyManager->getRawKeyMaterial($cacheKey);

        $cacheKeyL = Binary::safeSubstr(
            $rawCacheKey->getString(),
            0,
            SODIUM_CRYPTO_SHORTHASH_KEYBYTES
        );
        $cacheKeyR = Binary::safeSubstr(
            $rawCacheKey->getString(),
            SODIUM_CRYPTO_SHORTHASH_KEYBYTES,
            SODIUM_CRYPTO_SHORTHASH_KEYBYTES
        );

        $this->keyManager->addMetadata($vault, 'cache_key_l', $cacheKeyL);
        $this->keyManager->addMetadata($vault, 'cache_key_r', $cacheKeyR);

        $this->keyManager->saveKeyring($this->authKey);
    }

    public function deleteVault(string $vault): void
    {
        $options = $this->setDefaultSharedOptions([
            'delete_all' => true,
            'vault' => $vault,
        ]);

        $resolver = new OptionsResolver();
        $this->adapter->configureSharedOptions($resolver);
        $this->adapter->configureDeleteSecretOptions($resolver);

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
        $options = $this->setDefaultSharedOptions($options);

        $shmKey = $this->getSHMKey($key);

        $resolver = new OptionsResolver();
        $this->adapter->configureSharedOptions($resolver);
        $this->adapter->configureGetSecretOptions($resolver);

        return $this->adapter->getSecret($shmKey, $resolver->resolve($options));
    }

    public function get(string $key): mixed
    {
        $this->throwMissingVaultExceptionIfMissing();

        try {
            $secret = $this->getSecret($key, $this->options);
        } catch (SecretNotFoundException $ignored) {
            return null;
        }

        if (!$secret->isEncrypted()) {
            return $secret->getValue();
        }

        $data = $this->decryptValue($secret);

        if ($this->authKey) {
            $data = $this->verifyData($data);
        }

        try {
            return json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $exception) {
            return null;
        }
    }

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        $options = $this->setDefaultSharedOptions($options);

        $resolver = new OptionsResolver();
        $this->adapter->configureSharedOptions($resolver);
        $this->adapter->configurePutSecretOptions($resolver);

        return $this->adapter->putSecret($secret, $resolver->resolve($options));
    }

    public function set(string $key, mixed $value): bool
    {
        $this->throwMissingVaultExceptionIfMissing();

        try {
            $value = json_encode($value, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        } catch (\Exception $exception) {
            return false;
        }

        if ($this->authKey) {
            $value = $this->authenticateData($value);
        }

        $dataKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $dataKey = $this->keyManager->generateKey($dataKeyConfig);

        try {
            $encryptedDataKey = $this->encryptDataKey($dataKey);
        } catch (UnableToEncryptMessageException $exception) {
            return false;
        }

        try {
            $encryptedValue = $this->encryptValue($dataKey, $value);
        } catch (UnableToEncryptMessageException $exception) {
            return false;
        }

        $shmKey = $this->getSHMKey($key);

        $secret = new Secret($shmKey, $encryptedDataKey, $encryptedValue, true);

        try {
            $this->putSecret($secret, $this->options);
        } catch (\Exception $exception) {
            return false;
        }

        return true;
    }

    public function deleteSecretByKey(string $key, array $options = []): void
    {
        $secret = $this->getSecret($key, $options);

        $this->deleteSecret($secret, $options);
    }

    public function deleteSecret(SecretInterface $secret, array $options = []): void
    {
        $options = $this->setDefaultSharedOptions($options);

        $resolver = new OptionsResolver();
        $this->adapter->configureSharedOptions($resolver);
        $this->adapter->configureDeleteSecretOptions($resolver);

        $this->adapter->deleteSecret($secret, $resolver->resolve($options));
    }

    public function delete(string $key): bool
    {
        $this->throwMissingVaultExceptionIfMissing();

        try {
            $this->deleteSecretByKey($key, $this->options);
        } catch (\Exception $exception) {
            return false;
        }

        return true;
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

    private function authenticateData(string $value): string
    {
        $encryptionAdapter = $this->keyManager->getEncryptionAdapter();

        $config = [
            EncryptionRequestInterface::CHOOSE_ENCODER => true,
        ];

        $request = new MessageEncryptionRequest(new HiddenString($value), $this->authKey, $config);

        try {
            $mac = $encryptionAdapter->authenticate($request);
        } catch (UnableToEncryptMessageException $exception) {
            return $value;
        }

        return $mac . $value;
    }

    private function verifyData(string $data): string
    {
        $mac = Utility::subString($data, 0, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        $data = Utility::subString($data, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);

        $encryptionAdapter = $this->keyManager->getEncryptionAdapter();

        $config = [
            EncryptionRequestInterface::MAC => $mac,
            EncryptionRequestInterface::CHOOSE_ENCODER => true,
        ];

        $request = new MessageEncryptionRequest(new HiddenString($data), $this->authKey, $config);

        if (!$encryptionAdapter->verify($request)) {
            throw new SecretNotFoundException('Secret data could not be verified.');
        }

        return $data;
    }

    private function encryptValue(KeyInterface $key, string $value): string
    {
        $encryptionAdapter = $this->keyManager->getEncryptionAdapter();

        $request = new MessageEncryptionRequest(new HiddenString($value), $key);

        return $encryptionAdapter->encrypt($request);
    }

    private function decryptValue(SecretInterface $secret): string
    {
        $encryptionAdapter = $this->keyManager->getEncryptionAdapter();

        $dataKey = $this->decryptDataKey($secret);

        $request = new MessageEncryptionRequest(new HiddenString($secret->getValue()), $dataKey);

        try {
            return $encryptionAdapter->decrypt($request)->getString();
        } catch (UnableToEncryptMessageException $exception) {
            return '';
        }
    }

    private function encryptDataKey(KeyInterface $key): string
    {
        $encryptionAdapter = $this->keyManager->getEncryptionAdapter();

        $kmsKey = $this->keyManager->getKey($this->vault, 'kms_key');

        $dataKey = [
            'hex' => $key->getHex()->getString(),
            'type' => $key->getType(),
            'version' => $key->getVersion(),
            'adapter' => $key->getAdapter(),
        ];
        $dataKey = json_encode($dataKey, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);

        $request = new MessageEncryptionRequest(new HiddenString($dataKey), $kmsKey);

        return $encryptionAdapter->encrypt($request);
    }

    private function decryptDataKey(SecretInterface $secret): KeyInterface
    {
        $encryptionAdapter = $this->keyManager->getEncryptionAdapter();

        $kmsKey = $this->keyManager->getKey($this->vault, 'kms_key');
        $encryptedDataKey = $secret->getKey();

        $request = new MessageEncryptionRequest(new HiddenString($encryptedDataKey), $kmsKey);

        try {
            $data = json_decode($encryptionAdapter->decrypt($request)->getString(), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException('Could not decrypt the secrets data key.', $exception);
        }

        $keyFactory = $this->keyManager->getKeyFactory();
        return $keyFactory->buildKeyFromRawKeyData($data['hex'], $data['type'], $data['adapter'], $data['version']);
    }

    private function getSHMKey(string $lookup): string
    {
        return Base64UrlSafe::encode(
            \sodium_crypto_shorthash(
                $this->vault . $lookup,
                $this->keyManager->getMetadata($this->vault, 'cache_key_l')
            ) .
            \sodium_crypto_shorthash(
                $this->vault . $lookup,
                $this->keyManager->getMetadata($this->vault, 'cache_key_r')
            )
        );
    }

    private function setDefaultSharedOptions($options): array
    {
        $options = array_merge($options, $this->options);

        $vault = $this->vault;
        if (isset($options['vault'])) {
            $vault = $options['vault'];
        }

        if ($this->vault === '' && $vault !== '') {
            $this->vault = $vault;
        }

        $this->throwMissingVaultExceptionIfMissing();

        if (!isset($options['vault'])) {
            $options['vault'] = $this->vault;
        }

        return $options;
    }

    private function throwMissingVaultExceptionIfMissing(): void
    {
        if ($this->vault === '') {
            throw new UnableToAccessRestrictedCommandsException('Cannot access secrets without first calling "vault(\'vault_name\')".');
        }
    }

    public function getVaultAdapter(): VaultAdapterInterface
    {
        return $this->adapter;
    }
}
