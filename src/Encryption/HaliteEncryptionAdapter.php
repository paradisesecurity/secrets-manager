<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\FileEncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Factory\HaliteKeyFactoryAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProviderInterface;
use ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;
use ParagonIE\Halite\Config as HaliteConfig;
use ParagonIE\Halite\Contract\StreamInterface;
use ParagonIE\Halite\File as HaliteFile;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\Key as HaliteKey;
use ParagonIE\Halite\KeyPair as HaliteKeyPair;
use ParagonIE\Halite\Stream\MutableFile;
use ParagonIE\Halite\Stream\ReadOnlyFile;
use ParagonIE\Halite\Symmetric\Crypto as SymmetricCrypto;
use ParagonIE\HiddenString\HiddenString;

use function in_array;
use function is_bool;
use function is_null;
use function is_string;

class HaliteEncryptionAdapter extends AbstractEncryptionAdapter implements EncryptionAdapterInterface
{
    public const ADAPTER_NAME = 'halite';

    public const CURRENT_VERSION = Halite::VERSION;

    public const SYMMETRIC_CONFIG = 'symmetric_config';

    public const ASYMMETRIC_CONFIG = 'asymmetric_config';

    public function __construct(
        AdapterBasedKeyProviderInterface $adapterBasedKeyProvider
    ) {
        $this->name = self::ADAPTER_NAME;
        $this->version = self::CURRENT_VERSION;

        parent::__construct($adapterBasedKeyProvider);
    }

    public function getRequiredEncryptionKeyType(): string
    {
        return HaliteKeyFactoryAdapter::HALITE_KEY;
    }

    public function checksum(EncryptionRequestInterface $request): string
    {
        $encoding = $this->processEncodingConfig($request);

        try {
            $key = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY, KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY]);
        } catch (UnableToEncryptMessageException) {
            $key = null;
        }

        $input = $this->processHaliteFile($request->getInputFile(), 'input');

        try {
            return HaliteFile::checksum($input, $key, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to calculate the BLAKE2b-512 checksum of the file.', $exception);
        }
    }

    public function seal(EncryptionRequestInterface $request): string|int
    {
        $publicKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY]);

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->processHaliteFile($request->getInputFile(), 'input');
            $output = $this->processHaliteFile($request->getOutputFile(), 'output');

            $additionalData = $request->getAdditionalData();
            $additionalData = !empty($additionalData) ? $additionalData : null;

            return HaliteFile::seal($input, $output, $publicKey, $additionalData);
        }

        $message = $request->getMessage();
        $encoding = $this->processEncodingConfig($request);

        try {
            return AsymmetricCrypto::seal($message, $publicKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to encrypt a message with the recipient\'s public key.', $exception);
        }
    }

    public function sign(EncryptionRequestInterface $request): string
    {
        $encoding = $this->processEncodingConfig($request);

        $privateKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY]);

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->processHaliteFile($request->getInputFile(), 'input');

            return HaliteFile::sign($input, $privateKey, $encoding);
        }

        $message = $request->getMessage()->getString();

        try {
            return AsymmetricCrypto::sign($message, $privateKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to sign message with private key.', $exception);
        }
    }

    public function signAndEncrypt(EncryptionRequestInterface $request): string
    {
        $message = $request->getMessage();
        $encoding = $this->processEncodingConfig($request);

        $secretKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY]);
        $recipientPublicKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY, KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY]);

        try {
            return AsymmetricCrypto::signAndEncrypt($message, $secretKey, $recipientPublicKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to sign message and encrypt it with the recipient\'s public key.', $exception);
        }
    }

    public function unseal(EncryptionRequestInterface $request): HiddenString|bool
    {
        $privateKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY]);

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->processHaliteFile($request->getInputFile(), 'input');
            $output = $this->processHaliteFile($request->getOutputFile(), 'output');

            $additionalData = $request->getAdditionalData();
            $additionalData = !empty($additionalData) ? $additionalData : null;

            return HaliteFile::unseal($input, $output, $privateKey, $additionalData);
        }

        $message = $request->getMessage()->getString();
        $encoding = $this->processEncodingConfig($request);

        try {
            return AsymmetricCrypto::unseal($message, $privateKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to decrypt sealed message with the private key.', $exception);
        }
    }

    public function verify(EncryptionRequestInterface $request): bool
    {
        if ($request->isAsymmetric()) {
            return $this->asymmetricVerify($request);
        }

        return $this->symmetricVerify($request);
    }

    private function asymmetricVerify(EncryptionRequestInterface $request): bool
    {
        $encoding = $this->processEncodingConfig($request);
        $signature = $request->getSignature();
        $signature = ($signature ? $signature : '');

        $publicKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY]);

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->processHaliteFile($request->getInputFile(), 'input');

            return HaliteFile::verify($input, $publicKey, $signature, $encoding);
        }

        $message = $request->getMessage()->getString();

        try {
            return AsymmetricCrypto::verify($message, $publicKey, $signature, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to verify a signed message with the correct public key.', $exception);
        }
    }

    private function symmetricVerify(EncryptionRequestInterface $request): bool
    {
        $config = $this->processConfig($request);
        $message = $request->getMessage()->getString();
        $encoding = $this->processEncodingConfig($request);
        $mac = $request->getMac();
        $mac = ($mac ? $mac : '');

        $secretKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY]);

        $symmetricConfig = $this->processHaliteConfig(self::SYMMETRIC_CONFIG, $config);

        try {
            return SymmetricCrypto::verify($message, $secretKey, $mac, $encoding, $symmetricConfig);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to verify the authenticity of the message, given the shared MAC key.', $exception);
        }
    }

    public function verifyAndDecrypt(EncryptionRequestInterface $request): HiddenString
    {
        $message = $request->getMessage()->getString();
        $encoding = $this->processEncodingConfig($request);

        $senderPublicKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY]);
        $givenSecretKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY, KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY]);

        try {
            return AsymmetricCrypto::verifyAndDecrypt($message, $senderPublicKey, $givenSecretKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to decrypt the message and verify its signature.', $exception);
        }
    }

    private function asymmetricEncryptOrDecrypt(
        EncryptionRequestInterface $request,
        bool $decrypt = false
    ): HiddenString|string|bool|int {
        $additionalData = $request->getAdditionalData();

        $ourPrivateKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY]);
        $theirPublicKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY]);

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->processHaliteFile($request->getInputFile(), 'input');
            $output = $this->processHaliteFile($request->getOutputFile(), 'output');

            $additionalData = !empty($additionalData) ? $additionalData : null;

            if ($decrypt) {
                return HaliteFile::asymmetricDecrypt($input, $output, $ourPrivateKey, $theirPublicKey, $additionalData);
            }

            return HaliteFile::asymmetricEncrypt($input, $output, $theirPublicKey, $ourPrivateKey, $additionalData);
        }

        $message = $request->getMessage();
        $encoding = $this->processEncodingConfig($request);

        if ($decrypt) {
            $message = $message->getString();
            return AsymmetricCrypto::decryptWithAD($message, $ourPrivateKey, $theirPublicKey, $additionalData, $encoding);
        }

        return AsymmetricCrypto::encryptWithAD($message, $ourPrivateKey, $theirPublicKey, $additionalData, $encoding);
    }

    private function symmetricEncryptOrDecrypt(
        EncryptionRequestInterface $request,
        bool $decrypt = false
    ): HiddenString|string|bool|int {
        $additionalData = $request->getAdditionalData();

        $secretKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY]);

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->processHaliteFile($request->getInputFile(), 'input');
            $output = $this->processHaliteFile($request->getOutputFile(), 'output');

            $additionalData = !empty($additionalData) ? $additionalData : null;

            if ($decrypt) {
                return HaliteFile::decrypt($input, $output, $secretKey, $additionalData);
            }

            return HaliteFile::encrypt($input, $output, $secretKey, $additionalData);
        }

        $message = $request->getMessage();
        $encoding = $this->processEncodingConfig($request);

        if ($decrypt) {
            $message = $message->getString();
            return SymmetricCrypto::decryptWithAD($message, $secretKey, $additionalData, $encoding);
        }

        return SymmetricCrypto::encryptWithAD($message, $secretKey, $additionalData, $encoding);
    }

    public function decrypt(EncryptionRequestInterface $request): HiddenString|bool
    {
        if ($request->isAsymmetric()) {
            try {
                return $this->asymmetricEncryptOrDecrypt($request, true);
            } catch (\Exception $exception) {
                throw new UnableToEncryptMessageException('Unable to decrypt message using asymmetric cryptography.', $exception);
            }
        }

        try {
            return $this->symmetricEncryptOrDecrypt($request, true);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to decrypt message using the Halite encryption protocol.', $exception);
        }
    }

    public function encrypt(EncryptionRequestInterface $request): string|int
    {
        if ($request->isAsymmetric()) {
            try {
                return $this->asymmetricEncryptOrDecrypt($request);
            } catch (\Exception $exception) {
                throw new UnableToEncryptMessageException('Unable to encrypt message using asymmetric cryptography.', $exception);
            }
        }

        try {
            return $this->symmetricEncryptOrDecrypt($request);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to encrypt message using the Halite encryption protocol.', $exception);
        }
    }

    public function authenticate(EncryptionRequestInterface $request): string
    {
        $message = $request->getMessage()->getString();
        $encoding = $this->processEncodingConfig($request);

        $secretKey = $this->determineCorrectKeyInstance($request->getKeys(), [KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY]);

        try {
            return SymmetricCrypto::authenticate($message, $secretKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException('Unable to authenticate message.', $exception);
        }
    }

    private function processHaliteFile(mixed $file, string $source): StreamInterface|string
    {
        if (is_string($file)) {
            return $file;
        }

        if (!is_resource($file)) {
            return '';
        }

        if ($source === 'input') {
            return new ReadOnlyFile($file);
        }

        if ($source === 'output') {
            return new MutableFile($file);
        }
    }

    private function processHaliteConfig(string $name, array $config): HaliteConfig|null
    {
        if (!isset($config[$name])) {
            return null;
        }
        $haliteConfig = $config[$name];
        if ($haliteConfig instanceof HaliteConfig) {
            return $haliteConfig;
        }
        return null;
    }

    private function processEncodingConfig(EncryptionRequestInterface $request): string|bool
    {
        $defaultEncoding = Halite::ENCODE_BASE64URLSAFE;
        $encoding = $request->getEncoding();
        if (is_string($encoding)) {
            $defaultEncoding = $encoding;
        }
        $chooseEncoder = $request->chooseEncoder();
        if (is_bool($chooseEncoder)) {
            $defaultEncoding = $chooseEncoder;
        }
        return $defaultEncoding;
    }

    private function determineCorrectKeyInstance(
        array $keys,
        array $types
    ): HaliteKey|HaliteKeyPair {
        try {
            return $this->findKeyOrThrowError($keys, $types);
        } catch (UnableToEncryptMessageException $exception) {
            $keys = $this->splitKeyPairs($keys);
            return $this->findKeyOrThrowError($keys, $types);
        }
    }

    private function findKeyOrThrowError(
        array $keys,
        array $types
    ): HaliteKey|HaliteKeyPair {
        foreach ($keys as $key) {
            if (in_array($key->getType(), $types, true)) {
                return $this->getHaliteKey($key);
            }
        }

        $this->unableToEncryptMessageWithMissingKey($types);
    }

    private function splitKeyPairs(array $keys): array
    {
        $keyType = $this->getRequiredEncryptionKeyType();
        $keyFactoryAdapter = $this->getAdapterAppropriateKey($keyType);

        foreach ($keys as $key) {
            if (!$keyFactoryAdapter->isKeyPair($key->getType())) {
                continue;
            }
            $splitKeys = $keyFactoryAdapter->splitKeyPair($key, $keyType);
            $keys = array_merge($keys, $splitKeys);
        }

        return $keys;
    }

    private function getHaliteKey(KeyInterface $key): HaliteKey|HaliteKeyPair
    {
        $keyType = $this->getRequiredEncryptionKeyType();
        $keyFactoryAdapter = $this->getAdapterAppropriateKey($keyType);
        return $keyFactoryAdapter->getAdapterRequiredKey($key, $keyType);
    }

    private function processConfig(EncryptionRequestInterface $request): array
    {
        $version = $request->getVersion();
        if (is_null($version)) {
            $version = $this->getVersion();
            $request->setVersion($version);
        }
        $defaultConfig = $this->getVersionedConfig($version);
        $newConfig = $request->getConfiguration();
        return $this->replaceDefaultConfigValues($defaultConfig, $newConfig);
    }

    private function getVersionedConfig(string $version): array
    {
        return [
            self::SYMMETRIC_CONFIG => null,
            self::ASYMMETRIC_CONFIG => null,
        ];
    }
}
