<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite;

use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\FileEncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParagonIE\Halite\File as HaliteFile;
use ParagonIE\Halite\Symmetric\Crypto as SymmetricCrypto;
use ParagonIE\HiddenString\HiddenString;

/**
 * Handles symmetric cryptographic operations using Halite.
 */
final class HaliteSymmetricCrypto
{
    public function __construct(
        private HaliteKeyResolver $keyResolver,
        private HaliteConfigProcessor $configProcessor,
        private HaliteFileHandler $fileHandler,
    ) {
    }

    /**
     * Encrypts data using symmetric encryption.
     */
    public function encrypt(EncryptionRequestInterface $request): string|int
    {
        $secretKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            return $this->encryptFile($request, $secretKey);
        }

        return $this->encryptMessage($request, $secretKey);
    }

    /**
     * Decrypts data using symmetric encryption.
     */
    public function decrypt(EncryptionRequestInterface $request): HiddenString|bool
    {
        $secretKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY]
        );

        if ($request instanceof FileEncryptionRequestInterface) {
            return $this->decryptFile($request, $secretKey);
        }

        return $this->decryptMessage($request, $secretKey);
    }

    /**
     * Verifies symmetric authentication MAC.
     */
    public function verify(EncryptionRequestInterface $request): bool
    {
        $config = $this->configProcessor->processConfig($request);
        $encoding = $this->configProcessor->processEncoding($request);
        $mac = $request->getMac() ?? '';

        $secretKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY]
        );

        $message = $request->getMessage()->getString();
        $symmetricConfig = $this->configProcessor->extractSymmetricConfig($config);

        try {
            return SymmetricCrypto::verify($message, $secretKey, $mac, $encoding, $symmetricConfig);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to verify MAC with symmetric key.',
                $exception
            );
        }
    }

    /**
     * Generates authentication MAC.
     */
    public function authenticate(EncryptionRequestInterface $request): string
    {
        $message = $request->getMessage()->getString();
        $encoding = $this->configProcessor->processEncoding($request);

        $secretKey = $this->keyResolver->resolveKey(
            $request->getKeys(),
            [KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY]
        );

        try {
            return SymmetricCrypto::authenticate($message, $secretKey, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to authenticate message.',
                $exception
            );
        }
    }

    private function encryptFile(FileEncryptionRequestInterface $request, $secretKey): int
    {
        $input = $this->fileHandler->processInputFile($request->getInputFile());
        $output = $this->fileHandler->processOutputFile($request->getOutputFile());
        $additionalData = $request->getAdditionalData() ?: null;

        try {
            return HaliteFile::encrypt($input, $output, $secretKey, $additionalData);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to encrypt file with symmetric key.',
                $exception
            );
        }
    }

    private function encryptMessage(EncryptionRequestInterface $request, $secretKey): string
    {
        $message = $request->getMessage();
        $encoding = $this->configProcessor->processEncoding($request);
        $additionalData = $request->getAdditionalData();

        try {
            return SymmetricCrypto::encryptWithAD($message, $secretKey, $additionalData, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to encrypt message with symmetric key.',
                $exception
            );
        }
    }

    private function decryptFile(FileEncryptionRequestInterface $request, $secretKey): bool
    {
        $input = $this->fileHandler->processInputFile($request->getInputFile());
        $output = $this->fileHandler->processOutputFile($request->getOutputFile());
        $additionalData = $request->getAdditionalData() ?: null;

        try {
            return HaliteFile::decrypt($input, $output, $secretKey, $additionalData);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to decrypt file with symmetric key.',
                $exception
            );
        }
    }

    private function decryptMessage(EncryptionRequestInterface $request, $secretKey): HiddenString
    {
        $message = $request->getMessage()->getString();
        $encoding = $this->configProcessor->processEncoding($request);
        $additionalData = $request->getAdditionalData();

        try {
            return SymmetricCrypto::decryptWithAD($message, $secretKey, $additionalData, $encoding);
        } catch (\Exception $exception) {
            throw new UnableToEncryptMessageException(
                'Unable to decrypt message with symmetric key.',
                $exception
            );
        }
    }
}
