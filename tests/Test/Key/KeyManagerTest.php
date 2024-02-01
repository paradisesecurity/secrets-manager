<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\FileEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Encryption\HaliteEncryptionAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactory;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManager;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\File\FlysystemFilesystemAdapter;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\Keyring;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManager;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParadiseSecurity\Component\SecretsManager\Test\MockTrait;
use ParagonIE\HiddenString\HiddenString;

use function json_encode;
use function dirname;
use function chmod;
use function file_put_contents;
use function fopen;
use function fclose;
use function unlink;

final class KeyManagerTest extends TestCase
{
    use MockTrait;

    private $filesystemManager;

    private $masterKeyProvider;

    private $encryptionAdapter;

    private $keyFactory;

    private $tempDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempDir = dirname(__DIR__, 2);
        chmod($this->tempDir.'/tmp/', 0777);

        $this->filesystemManager = $this->getMockBuilder(FilesystemManagerInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(FilesystemManager::class))
            ->getMock();
        $this->masterKeyProvider = $this->getMockBuilder(MasterKeyProviderInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(MasterKeyProvider::class))
            ->getMock();
        $this->encryptionAdapter = $this->getMockBuilder(EncryptionAdapterInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(HaliteEncryptionAdapter::class))
            ->getMock();
        $this->keyFactory = $this->getMockBuilder(KeyFactoryInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(KeyFactory::class))
            ->getMock();
    }

    public function testConstruct(): void
    {
        $manager = $this->getManager();

        $this->assertInstanceOf(KeyManagerInterface::class, $manager);
    }

    public function testNewKeyring(): void
    {
        $manager = $this->getManager();

        $auth = $this->getExampleAuthenticationKey();

        $manager->newKeyring($auth);

        $manager->addMetadata('my_secrets', 'access_pin', '12345');

        $encryptionKey = $this->getExampleEncryptionKey();
        $manager->addKey('my_secrets', 'encryption_key', $encryptionKey);

        $this->assertTrue($manager->hasVault('my_secrets'));

        $value = $manager->getMetadata('my_secrets', 'access_pin');
        $this->assertSame($value, '12345');

        $key = $manager->getKey('my_secrets', 'encryption_key');
        $this->assertSame($key->getType(), KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);

        $manager->lockKeyring($auth);
        $manager->addKey('my_secrets', 'auth_key', $auth);
        $badKey = $manager->getKey('my_secrets', 'auth_key');
        $this->assertSame($badKey, null);
    }

    public function testLoadKeyring(): void
    {
        $manager = $this->getManager();

        $auth = $this->getExampleAuthenticationKey();

        file_put_contents($this->tempDir.'/tmp/example.keyring', $this->getExampleKeyring());
        chmod($this->tempDir.'/tmp/example.keyring', 0777);

        $exampleKeyring = fopen($this->tempDir.'/tmp/example.keyring', 'rb');

        $filesystem = $this->getMockFilesystemAdapter();
        $this->filesystemManager->expects($this->exactly(3))
            ->method('getFilesystem')
            ->withAnyParameters()
            ->willReturn($filesystem);
        $filesystem->expects($this->exactly(2))
            ->method('read')
            ->withAnyParameters()
            ->willReturnOnConsecutiveCalls(
                'G8cjsXnCuWWp1-vKp0GHa-fPCFE5FftgjF8gkfupqwsrhCTrwDosWLk8xuH35mW54_ternPVle2iL9e1MUJehw==8YOj-8-MbLGsdnYUz_q17BYhR5UpQSSvlucFSDlhSCq4tp454MUli29lmznxFh7ZcYcXXfQcRFWHcuApnPEEDg==',
                $this->getExampleKeyring()
            );
        $filesystem->expects($this->exactly(1))
            ->method('open')
            ->withAnyParameters()
            ->willReturn($exampleKeyring);
        $this->encryptionAdapter->expects($this->exactly(1))
            ->method('checksum')
            ->withAnyParameters()
            ->willReturn('G8cjsXnCuWWp1-vKp0GHa-fPCFE5FftgjF8gkfupqwsrhCTrwDosWLk8xuH35mW54_ternPVle2iL9e1MUJehw==');
        $this->masterKeyProvider->expects($this->exactly(1))
            ->method('getSignaturePublicKey')
            ->withAnyParameters()
            ->willReturn($this->getExampleSignaturePublicKey());
        $this->masterKeyProvider->expects($this->exactly(1))
            ->method('hasSignatureKeyPair')
            ->willReturn(false);
        $this->encryptionAdapter->expects($this->exactly(3))
            ->method('verify')
            ->withAnyParameters()
            ->willReturn(true);
        $this->masterKeyProvider->expects($this->exactly(1))
            ->method('getEncryptionKey')
            ->willReturn($this->getExampleEncryptionKey());
        $this->encryptionAdapter->expects($this->exactly(1))
            ->method('decrypt')
            ->withAnyParameters()
            ->willReturn(new HiddenString($this->getExampleKeyring()));
        $this->encryptionAdapter->expects($this->exactly(2))
            ->method('authenticate')
            ->withAnyParameters()
            ->willReturn('KChHV4LyeZnCDxcBHCl5qvOIdl630fTtQj2Cw5ZQUCIwstjhNDU4AvpNv_D_qFFIx3itAZAercdEYfZ5Z9cb3w==');

        $manager->loadKeyring($auth);

        fclose($exampleKeyring);
        unlink($this->tempDir.'/tmp/example.keyring');

        $this->assertTrue($manager->hasVault('my_secrets'));

        $publicKey = $this->getExampleSignaturePublicKey();
        $manager->addKey('my_secrets', 'public_key', $publicKey);
        $badKey = $manager->getKey('my_secrets', 'public_key');
        $this->assertSame($badKey, null);

        $key = $manager->getKey('my_secrets', 'encryption_key');
        $this->assertSame($key->getType(), KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);

        $value = $manager->getMetadata('my_secrets', 'access_pin');
        $this->assertSame($value, '12345');

        $manager->unlockKeyring($auth);
        $manager->addKey('my_secrets', 'public_key', $publicKey);
        $goodKey = $manager->getKey('my_secrets', 'public_key');
        $this->assertSame($goodKey->getHex()->getString(), $publicKey->getHex()->getString());
    }

    protected function getExampleKeyring(): string
    {
        $keyring = new Keyring();

        $keyring = $keyring->withSecuredData(
            'HC9JuFvtSZuD9oZSjJ6l1nGpuUwzXmmEV7rBQSsxIi6DvGpI39E0zO-NotSPMav7',
            [
                'my_secrets' => [
                    'encryption_key' => [
                        'hex' => '901b3eccb6d802776156e8ec93763c5f5b494d496fc56eef51f83efd8f9b7d78',
                        'type' => 'symmetric_encryption_key',
                        'adapter' => 'halite',
                        'version' => '5.0.0',
                    ],
                    'metadata' => [
                        'access_pin' => '12345'
                    ]
                ]
            ],
            [
                'KChHV4LyeZnCDxcBHCl5qvOIdl630fTtQj2Cw5ZQUCIwstjhNDU4AvpNv_D_qFFIx3itAZAercdEYfZ5Z9cb3w=='
            ]
        );

        return json_encode($keyring, JSON_PRETTY_PRINT);
    }

    protected function getExampleSignaturePublicKey(): KeyInterface
    {
        return new Key(
            new HiddenString(
                '4af75f7fc8051778a86944e45a2c9643145401c62552e147d719c6c831b7864a'
            ),
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
    }

    protected function getExampleEncryptionKey(): KeyInterface
    {
        return new Key(
            new HiddenString(
                '901b3eccb6d802776156e8ec93763c5f5b494d496fc56eef51f83efd8f9b7d78'
            ),
            KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
    }

    protected function getExampleAuthenticationKey(): KeyInterface
    {
        return new Key(
            new HiddenString(
                'f7aa52e4f3ae20457124887d563a3d638b678a058f89d6be8427bc9229c89e8a'
            ),
            KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
    }

    protected function getMockFilesystemAdapter(): FilesystemAdapterInterface
    {
        return $this->getMockBuilder(FilesystemAdapterInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(FlysystemFilesystemAdapter::class))
            ->getMock();
    }

    protected function getManager(): KeyManagerInterface
    {
        $this->masterKeyProvider->expects($this->exactly(1))
            ->method('setAccessor')
            ->withAnyParameters();

        $manager = new KeyManager($this->filesystemManager, $this->masterKeyProvider, $this->encryptionAdapter, $this->keyFactory);

        $manager->setAccessor($this->masterKeyProvider, $manager, '123-accessor');

        return $manager;
    }
}
