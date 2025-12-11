<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite;

use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\FileEncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;
use ParagonIE\Halite\File as HaliteFile;
use ParagonIE\HiddenString\HiddenString;

/**
 * Handles asymmetric cryptographic operations using Halite.
 */
final class HaliteAsymmetricCrypto
{
    public function __construct(
        private HaliteKeyResolver $keyResolver,
        private HaliteConfigProcessor $configProcessor,
        private HaliteFileHandler $fileHandler,
    ) {
    }

    /**
     * Encrypts data using asymmetric encryption.
     */
    public function encrypt(EncryptionRequestInterface $request): string|int
    {
        $ourPrivateKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY]
        );

        $theirPublicKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            return $this->encryptFile($request, $ourPrivateKey, $theirPublicKey);
        }

        return $this->encryptMessage($request, $ourPrivateKey, $theirPublicKey);
    }

    /**
     * Decrypts data using asymmetric encryption.
     */
    public function decrypt(EncryptionRequestInterface $request): HiddenString|bool
    {
        $ourPrivateKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY]
        );

        $theirPublicKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            return $this->decryptFile($request, $ourPrivateKey, $theirPublicKey);
        }

        return $this->decryptMessage($request, $ourPrivateKey, $theirPublicKey);
    }

    /**
     * Signs data with private key.
     */
    public function sign(EncryptionRequestInterface $request): string
    {
        $encoding = $this->configProcessor->processEncoding($request);

        $privateKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->fileHandler->processInputFile($request->getInputFile());
            return HaliteFile::sign($input, $privateKey, $encoding);
        }

        $message = $request->getMessage()->getString();

        try {
            return AsymmetricCrypto::sign($message, $privateKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to sign message with private key.',
                $exception
            );
        }
    }

    /**
     * Verifies signature with public key.
     */
    public function verify(EncryptionRequestInterface $request): bool
    {
        $encoding = $this->configProcessor->processEncoding($request);
        $signature = $request->getSignature() ?? '';

        $publicKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->fileHandler->processInputFile($request->getInputFile());
            return HaliteFile::verify($input, $publicKey, $signature, $encoding);
        }

        $message = $request->getMessage()->getString();

        try {
            return AsymmetricCrypto::verify($message, $publicKey, $signature, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to verify signature with public key.',
                $exception
            );
        }
    }

    /**
     * Seals data (anonymous encryption).
     */
    public function seal(EncryptionRequestInterface $request): string|int
    {
        $publicKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->fileHandler->processInputFile($request->getInputFile());
            $output = $this->fileHandler->processOutputFile($request->getOutputFile());
            $additionalData = $request->getAdditionalData() ?: null;

            return HaliteFile::seal($input, $output, $publicKey, $additionalData);
        }

        $message = $request->getMessage();
        $encoding = $this->configProcessor->processEncoding($request);

        try {
            return AsymmetricCrypto::seal($message, $publicKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to seal message with public key.',
                $exception
            );
        }
    }

    /**
     * Unseals data (anonymous decryption).
     */
    public function unseal(EncryptionRequestInterface $request): HiddenString|bool
    {
        $privateKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            $input = $this->fileHandler->processInputFile($request->getInputFile());
            $output = $this->fileHandler->processOutputFile($request->getOutputFile());
            $additionalData = $request->getAdditionalData() ?: null;

            return HaliteFile::unseal($input, $output, $privateKey, $additionalData);
        }

        $message = $request->getMessage()->getString();
        $encoding = $this->configProcessor->processEncoding($request);

        try {
            return AsymmetricCrypto::unseal($message, $privateKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to unseal message with private key.',
                $exception
            );
        }
    }

    private function encryptFile(FileEncryptionRequestInterface $request, $ourPrivateKey, $theirPublicKey): int
    {
        $input = $this->fileHandler->processInputFile($request->getInputFile());
        $output = $this->fileHandler->processOutputFile($request->getOutputFile());
        $additionalData = $request->getAdditionalData() ?: null;

        try {
            return HaliteFile::asymmetricEncrypt(
                $input,
                $output,
                $theirPublicKey,
                $ourPrivateKey,
                $additionalData
            );
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to encrypt file with asymmetric keys.',
                $exception
            );
        }
    }

    private function encryptMessage(EncryptionRequestInterface $request, $ourPrivateKey, $theirPublicKey): string
    {
        $message = $request->getMessage();
        $encoding = $this->configProcessor->processEncoding($request);
        $additionalData = $request->getAdditionalData();

        try {
            return AsymmetricCrypto::encryptWithAD(
                $message,
                $ourPrivateKey,
                $theirPublicKey,
                $additionalData,
                $encoding
            );
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to encrypt message with asymmetric keys.',
                $exception
            );
        }
    }

    private function decryptFile(FileEncryptionRequestInterface $request, $ourPrivateKey, $theirPublicKey): bool
    {
        $input = $this->fileHandler->processInputFile($request->getInputFile());
        $output = $this->fileHandler->processOutputFile($request->getOutputFile());
        $additionalData = $request->getAdditionalData() ?: null;

        try {
            return HaliteFile::asymmetricDecrypt(
                $input,
                $output,
                $ourPrivateKey,
                $theirPublicKey,
                $additionalData
            );
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to decrypt file with asymmetric keys.',
                $exception
            );
        }
    }

    private function decryptMessage(EncryptionRequestInterface $request, $ourPrivateKey, $theirPublicKey): HiddenString
    {
        $message = $request->getMessage()->getString();
        $encoding = $this->configProcessor->processEncoding($request);
        $additionalData = $request->getAdditionalData();

        try {
            return AsymmetricCrypto::decryptWithAD(
                $message,
                $ourPrivateKey,
                $theirPublicKey,
                $additionalData,
                $encoding
            );
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to decrypt message with asymmetric keys.',
                $exception
            );
        }
    }

    /**
     * Signs and encrypts message.
     */
    public function signAndEncrypt(EncryptionRequestInterface $request): string
    {
        $message = $request->getMessage();
        $encoding = $this->configProcessor->processEncoding($request);

        $secretKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY]
        );

        $recipientPublicKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [
                KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
                KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY
            ]
        );

        try {
            return AsymmetricCrypto::signAndEncrypt(
                $message,
                $secretKey,
                $recipientPublicKey,
                $encoding
            );
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to sign and encrypt message.',
                $exception
            );
        }
    }

    /**
     * Verifies and decrypts message.
     */
    public function verifyAndDecrypt(EncryptionRequestInterface $request): HiddenString
    {
        $message = $request->getMessage()->getString();
        $encoding = $this->configProcessor->processEncoding($request);

        $senderPublicKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY]
        );

        $givenSecretKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [
                KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY,
                KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY
            ]
        );

        try {
            return AsymmetricCrypto::verifyAndDecrypt(
                $message,
                $senderPublicKey,
                $givenSecretKey,
                $encoding
            );
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to verify and decrypt message.',
                $exception
            );
        }
    }
}
