<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\HaliteEncryptionAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactory;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManager;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FlysystemFilesystemAdapter;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfig;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManager;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProvider;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParadiseSecurity\Component\SecretsManager\Test\MockTrait;
use ParagonIE\HiddenString\HiddenString;

final class KeyManagerRotationTest extends TestCase
{
    use MockTrait;

    private FilesystemManagerInterface $filesystemManager;
    private MasterKeyProviderInterface $masterKeyProvider;
    private HaliteEncryptionAdapter $encryptionAdapter;
    private KeyFactoryInterface $keyFactory;

    protected function setUp(): void
    {
        parent::setUp();

        // Use createStub() for dependencies that don't need expectations
        $this->filesystemManager = $this->createStub(FilesystemManagerInterface::class);
        
        // For masterKeyProvider, we need a mock because we verify setAccessor is called
        $this->masterKeyProvider = $this->createMock(MasterKeyProviderInterface::class);

        // Use createStub for encryptionAdapter since we only need it to return values
        $this->encryptionAdapter = $this->createStub(HaliteEncryptionAdapter::class);
        $this->encryptionAdapter->method('getName')->willReturn('halite');

        // Use createStub for keyFactory
        $this->keyFactory = $this->createStub(KeyFactoryInterface::class);
    }

    public function testRotateKeys(): void
    {
        $manager = $this->getManager();
        $auth = $this->getExampleAuthenticationKey();
        
        // Create a new keyring
        $manager->newKeyring($auth);
        $manager->unlockKeyring($auth);
        
        // Add a vault with a key
        $config = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $this->keyFactory->method('generateKey')
            ->willReturn($this->getExampleEncryptionKey());
            
        $manager->newKey('test_vault', 'test_key', $config);
        
        // Verify the key exists
        $this->assertTrue($manager->hasVault('test_vault'));
        $this->assertNotNull($manager->getKey('test_vault', 'test_key'));
        
        // Rotate the keys
        $result = $manager->rotateKeys('test_vault');
        $this->assertTrue($result);
        
        // Verify the key still exists (it should be replaced with a new one)
        $this->assertTrue($manager->hasVault('test_vault'));
        $this->assertNotNull($manager->getKey('test_vault', 'test_key'));
    }

    public function testRotateKeysWithSpecificKeys(): void
    {
        $manager = $this->getManager();
        $auth = $this->getExampleAuthenticationKey();
        
        // Create a new keyring
        $manager->newKeyring($auth);
        $manager->unlockKeyring($auth);
        
        // Add a vault with multiple keys
        $config = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $this->keyFactory->method('generateKey')
            ->willReturn($this->getExampleEncryptionKey());
            
        $manager->newKey('test_vault', 'key1', $config);
        $manager->newKey('test_vault', 'key2', $config);
        
        // Rotate only specific keys
        $result = $manager->rotateKeys('test_vault', ['key1']);
        $this->assertTrue($result);
        
        // Verify both keys still exist
        $this->assertNotNull($manager->getKey('test_vault', 'key1'));
        $this->assertNotNull($manager->getKey('test_vault', 'key2'));
    }

    public function testRotateKeysFailsWhenLocked(): void
    {
        $manager = $this->getManager();
        $auth = $this->getExampleAuthenticationKey();
        
        // Create a new keyring and lock it
        $manager->newKeyring($auth);
        $manager->lockKeyring($auth);
        
        // Attempt to rotate keys while locked
        $result = $manager->rotateKeys('test_vault');
        $this->assertFalse($result);
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

    protected function getMockFilesystemAdapter(): FilesystemAdapterInterface
    {
        return $this->createStub(FilesystemAdapterInterface::class);
    }

    protected function getManager(): KeyManagerInterface
    {
        // This is the ONLY expectation we need, so we use createMock for this one
        $this->masterKeyProvider->expects($this->once())
            ->method('setAccessor')
            ->with(
                $this->isInstanceOf(KeyManager::class),
                $this->identicalTo($this->masterKeyProvider)
            );

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
