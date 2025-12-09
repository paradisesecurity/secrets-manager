<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\HaliteEncryptionAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactory;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManager;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FlysystemFilesystemAdapter;
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

    private FilesystemManagerInterface $filesystemManager;
    private MasterKeyProviderInterface $masterKeyProvider;
    private EncryptionAdapterInterface $encryptionAdapter;
    private KeyFactoryInterface $keyFactory;
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempDir = dirname(__DIR__, 2);
        chmod($this->tempDir.'/tmp/', 0777);

        // Use createStub() for dependencies without expectations
        $this->filesystemManager = $this->createStub(FilesystemManagerInterface::class);
        $this->masterKeyProvider = $this->createStub(MasterKeyProviderInterface::class);
        $this->encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $this->keyFactory = $this->createStub(KeyFactoryInterface::class);
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
        $this->assertNull($badKey);
    }

    public function testLoadKeyring(): void
    {
        // For this test we need mocks with expectations, so recreate them
        $filesystemManager = $this->createMock(FilesystemManagerInterface::class);
        $masterKeyProvider = $this->createMock(MasterKeyProviderInterface::class);
        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $keyFactory = $this->createStub(KeyFactoryInterface::class);

        $auth = $this->getExampleAuthenticationKey();

        file_put_contents($this->tempDir.'/tmp/example.keyring', $this->getExampleKeyring());
        chmod($this->tempDir.'/tmp/example.keyring', 0777);

        $exampleKeyring = fopen($this->tempDir.'/tmp/example.keyring', 'rb');

        $filesystem = $this->createMock(FilesystemAdapterInterface::class);
        
        $filesystemManager->expects($this->exactly(3))
            ->method('getFilesystem')
            ->willReturn($filesystem);
            
        $filesystem->expects($this->exactly(2))
            ->method('read')
            ->willReturnOnConsecutiveCalls(
                'G8cjsXnCuWWp1-vKp0GHa-fPCFE5FftgjF8gkfupqwsrhCTrwDosWLk8xuH35mW54_ternPVle2iL9e1MUJehw==8YOj-8-MbLGsdnYUz_q17BYhR5UpQSSvlucFSDlhSCq4tp454MUli29lmznxFh7ZcYcXXfQcRFWHcuApnPEEDg==',
                $this->getExampleKeyring()
            );
            
        $filesystem->expects($this->once())
            ->method('open')
            ->willReturn($exampleKeyring);
            
        $encryptionAdapter->expects($this->once())
            ->method('checksum')
            ->willReturn('G8cjsXnCuWWp1-vKp0GHa-fPCFE5FftgjF8gkfupqwsrhCTrwDosWLk8xuH35mW54_ternPVle2iL9e1MUJehw==');
            
        $masterKeyProvider->expects($this->once())
            ->method('getSignaturePublicKey')
            ->willReturn($this->getExampleSignaturePublicKey());
            
        $masterKeyProvider->expects($this->once())
            ->method('hasSignatureKeyPair')
            ->willReturn(false);
            
        $encryptionAdapter->expects($this->exactly(3))
            ->method('verify')
            ->willReturn(true);
            
        $masterKeyProvider->expects($this->once())
            ->method('getEncryptionKey')
            ->willReturn($this->getExampleEncryptionKey());
            
        $encryptionAdapter->expects($this->once())
            ->method('decrypt')
            ->willReturn(new HiddenString($this->getExampleKeyring()));
            
        $encryptionAdapter->expects($this->exactly(2))
            ->method('authenticate')
            ->willReturn('KChHV4LyeZnCDxcBHCl5qvOIdl630fTtQj2Cw5ZQUCIwstjhNDU4AvpNv_D_qFFIx3itAZAercdEYfZ5Z9cb3w==');

        $masterKeyProvider->expects($this->once())
            ->method('setAccessor');

        // TODO: Update new dependencies requirment
        $manager = new KeyManager(
            $filesystemManager, 
            $masterKeyProvider, 
            $encryptionAdapter, 
            $keyFactory
        );
        
        $manager->setAccessor($masterKeyProvider, $manager, '123-accessor');

        $manager->loadKeyring($auth);

        fclose($exampleKeyring);
        unlink($this->tempDir.'/tmp/example.keyring');

        $this->assertTrue($manager->hasVault('my_secrets'));

        $publicKey = $this->getExampleSignaturePublicKey();
        $manager->addKey('my_secrets', 'public_key', $publicKey);
        $badKey = $manager->getKey('my_secrets', 'public_key');
        $this->assertNull($badKey);

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

    protected function getManager(): KeyManagerInterface
    {
        // Configure the stub to not complain about setAccessor
        $this->masterKeyProvider->method('setAccessor');

        // TODO: Update new dependencies requirment
        $manager = new KeyManager(
            $this->filesystemManager, 
            $this->masterKeyProvider, 
            $this->encryptionAdapter, 
            $this->keyFactory
        );

        $manager->setAccessor($this->masterKeyProvider, $manager, '123-accessor');

        return $manager;
    }
}
