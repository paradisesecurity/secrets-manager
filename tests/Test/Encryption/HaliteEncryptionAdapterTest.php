<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Encryption;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\EncryptionRequestInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\HaliteEncryptionAdapter;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\Builder\EncryptionRequestBuilder;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\HaliteKeyFactoryAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProvider;
use ParadiseSecurity\Component\ServiceRegistry\Registry\PrioritizedServiceRegistry;
use ParagonIE\Halite\KeyFactory as HaliteKeyFactory;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

use function str_repeat;
use function strlen;

final class HaliteEncryptionAdapterTest extends TestCase
{
    public function testAuthenticate()
    {
        $adapter = $this->getEncryptionAdapter();
        $message = 'test message';
        $request = EncryptionRequestBuilder::create()
            ->withKey($this->getSymmetricAuthenticationKey())
            ->buildForMessage(new HiddenString($message));
        $mac = $adapter->authenticate($request);
        $request->setMac($mac);
        $this->assertTrue(
            $adapter->verify($request)
        );
    }

    public function testAuthenticateFail()
    {
        $key = $this->getSymmetricAuthenticationKey();
        $adapter = $this->getEncryptionAdapter();
        $message = 'test message';
        $request = EncryptionRequestBuilder::create()
            ->withKey($key)
            ->buildForMessage(new HiddenString($message));
        $request->setChooseEncoder(true);
        $mac = $adapter->authenticate($request);
        $badRequest = new MessageEncryptionRequest(
            new HiddenString('othermessage'),
            $key,
        );
        $badRequest->setChooseEncoder(true);
        $badRequest->setMac($mac);
        $this->assertFalse(
            $adapter->verify($badRequest)
        );
        $badMac = $adapter->authenticate($badRequest);
        $request->setMac($badMac);
        $this->assertFalse(
            $adapter->verify($request)
        );
    }

    public function testSymmetricEncrypt(string $message = 'test message', array $options = [])
    {
        $key = $this->getSymmetricEncryptionKey();
        $adapter = $this->getEncryptionAdapter();
        $encryptionRequest = new MessageEncryptionRequest(
            new HiddenString($message),
            $key,
        );
        $encryptionRequest->addOptions($options);
        $ciphertext = $adapter->encrypt($encryptionRequest);
        $decryptionRequest = new MessageEncryptionRequest(
            new HiddenString($ciphertext),
            $key,
        );
        $decryptionRequest->addOptions($options);
        $plaintext = $adapter->decrypt($decryptionRequest);
        $this->assertSame($plaintext->getString(), $message);

        try {
            $decryptionRequest->setAdditionalData('wrong');
            $plaintext = $adapter->decrypt($decryptionRequest);
        } catch (UnableToEncryptMessageException $exception) {
            $this->assertSame(
                'Unable to decrypt message using the Halite encryption protocol.',
                $exception->getMessage()
            );
        }
    }

    public function testSymmetricEncryptLarge()
    {
        $message = str_repeat("\xff", 1 << 17);
        $this->testSymmetricEncrypt($message);
    }

    public function testSymmetricEncryptWithAdditionalData()
    {
        $options = [
            EncryptionRequestInterface::ADDITIONAL_DATA => 'test'
        ];
        $this->testSymmetricEncrypt('test message', $options);
    }

    public function testSymmetricEncryptEmpty()
    {
        $this->testSymmetricEncrypt('');
    }

    public function testSymmetricRawEncrypt()
    {
        $options = [
            EncryptionRequestInterface::CHOOSE_ENCODER => true
        ];
        $this->testSymmetricEncrypt('test message', $options);
    }

    public function testAsymmetricEncrypt(string $message = 'test message', array $options = [])
    {
        $alice = $this->getAsymmetricEncryptionKeyPair();
        $bob = $this->getAsymmetricEncryptionKeyPair();
        $adapter = $this->getEncryptionAdapter();
        $encryptionRequest = new MessageEncryptionRequest(
            new HiddenString($message),
            [$alice['key_pair'], $bob['public_key']]
        );
        $encryptionRequest->setAsymmetric(true);
        $encryptionRequest->addOptions($options);
        $ciphertext = $adapter->encrypt($encryptionRequest);
        $decryptionRequest = new MessageEncryptionRequest(
            new HiddenString($ciphertext),
            [$bob['key_pair'], $alice['public_key']]
        );
        $decryptionRequest->setAsymmetric(true);
        $decryptionRequest->addOptions($options);
        $plaintext = $adapter->decrypt($decryptionRequest);
        $this->assertSame($plaintext->getString(), $message);

        try {
            $decryptionRequest->setAdditionalData('wrong');
            $plaintext = $adapter->decrypt($decryptionRequest);
        } catch (UnableToEncryptMessageException $exception) {
            $this->assertSame(
                'Unable to decrypt message using asymmetric cryptography.',
                $exception->getMessage()
            );
        }
    }

    public function testAsymmetricEncryptWithAdditionalData()
    {
        $options = [
            EncryptionRequestInterface::ADDITIONAL_DATA => \random_bytes(32)
        ];
        $this->testAsymmetricEncrypt('test message', $options);
    }

    public function testAsymmetricEncryptEmpty()
    {
        $this->testAsymmetricEncrypt('');
    }

    public function testSeal()
    {
        $message = 'This is for your eyes only';
        $alice = $this->getAsymmetricEncryptionKeyPair();
        $adapter = $this->getEncryptionAdapter();
        $sealRequest = new MessageEncryptionRequest(
            new HiddenString($message),
            $alice['key_pair']
        );
        $sealRequest->setAsymmetric(true);
        $sealed = $adapter->seal($sealRequest);
        $unsealRequest = new MessageEncryptionRequest(
            new HiddenString($sealed),
            $alice['key_pair']
        );
        $unsealRequest->setAsymmetric(true);
        $opened = $adapter->unseal($unsealRequest);
        $this->assertSame($opened->getString(), $message);

        try {
            $badRequest = new MessageEncryptionRequest(
                new HiddenString($sealed),
                $this->getSymmetricEncryptionKey()
            );
            $badRequest->setAsymmetric(true);
            $opened = $adapter->unseal($badRequest);
        } catch (UnableToEncryptMessageException $exception) {
            $this->assertSame(
                'Incorrect key(s) supplied for encryption type, expected (Asymmetric Encryption Secret Key).',
                $exception->getMessage()
            );
        }
    }

    public function testSign()
    {
        $adapter = $this->getEncryptionAdapter();
        $alice = $this->getAsymmetricSignatureKeyPair();
        $message = 'test message';
        $signRequest = new MessageEncryptionRequest(
            new HiddenString($message),
            $alice['key_pair']
        );
        $signRequest->setAsymmetric(true);
        $signature = $adapter->sign($signRequest);
        $this->assertTrue(strlen($signature) === 88);
        $verifyRequest = new MessageEncryptionRequest(
            new HiddenString($message),
            $alice['key_pair']
        );
        $verifyRequest->setAsymmetric(true);
        $verifyRequest->setSignature($signature);
        $this->assertTrue($adapter->verify($verifyRequest));
    }

    public function testSignEncrypt(array $bob = [])
    {
        $adapter = $this->getEncryptionAdapter();
        $alice = $this->getAsymmetricSignatureKeyPair();
        if (empty($bob)) {
            $bob = $this->getAsymmetricEncryptionKeyPair();
        }
        $message = 'test message';
        $signRequest = new MessageEncryptionRequest(
            new HiddenString($message),
            [$alice['key_pair'], $bob['public_key']]
        );
        $signRequest->setAsymmetric(true);
        $encrypted = $adapter->signAndEncrypt($signRequest);
        $verifyRequest = new MessageEncryptionRequest(
            new HiddenString($encrypted),
            [$alice['public_key'], $bob['key_pair']]
        );
        $verifyRequest->setAsymmetric(true);
        $decrypted = $adapter->verifyAndDecrypt($verifyRequest);
        $this->assertSame(
            $message,
            $decrypted->getString()
        );
    }

    public function testSignEncryptWithSignatureKeyPair()
    {
        $bob = $this->getAsymmetricSignatureKeyPair();
        $this->testSignEncrypt($bob);
    }

    protected function getAsymmetricSignatureKeyPair(): array
    {
        $key = HaliteKeyFactory::generateSignatureKeyPair();
        $keypair = [];
        $keypair['key_pair'] = new Key(
            HaliteKeyFactory::export($key),
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
        $keypair['secret_key'] = new Key(
            HaliteKeyFactory::export($key->getSecretKey()),
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
        $keypair['public_key'] = new Key(
            HaliteKeyFactory::export($key->getPublicKey()),
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
        return $keypair;
    }

    protected function getAsymmetricEncryptionKeyPair(): array
    {
        $key = HaliteKeyFactory::generateEncryptionKeyPair();
        $keypair = [];
        $keypair['key_pair'] = new Key(
            HaliteKeyFactory::export($key),
            KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
        $keypair['secret_key'] = new Key(
            HaliteKeyFactory::export($key->getSecretKey()),
            KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
        $keypair['public_key'] = new Key(
            HaliteKeyFactory::export($key->getPublicKey()),
            KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
        return $keypair;
    }

    protected function getSymmetricEncryptionKey(): KeyInterface
    {
        $key = new EncryptionKey(
            new HiddenString(str_repeat('A', 32))
        );
        return new Key(
            HaliteKeyFactory::export($key),
            KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
    }

    protected function getSymmetricAuthenticationKey(): KeyInterface
    {
        $key = new AuthenticationKey(
            new HiddenString(str_repeat('A', 32))
        );
        return new Key(
            HaliteKeyFactory::export($key),
            KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
    }

    protected function getEncryptionAdapter(): EncryptionAdapterInterface
    {
        $haliteKeyFactoryAdapter = new HaliteKeyFactoryAdapter();

        $adapterRegistry = new PrioritizedServiceRegistry(KeyFactoryAdapterInterface::class);
        $adapterRegistry->register($haliteKeyFactoryAdapter);

        $adapterBasedKeyProvider = new AdapterBasedKeyProvider($adapterRegistry);

        return new HaliteEncryptionAdapter($adapterBasedKeyProvider);
    }
}
