<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Secret;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManager;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\ChainVaultAdapter;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManager;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\VaultAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Test\MockTrait;

final class SecretManagerSimpleRotationTest extends TestCase
{
    use MockTrait;

    private VaultAdapterInterface $adapter;
    private KeyManagerInterface $manager;
    private KeyInterface $auth;

    protected function setUp(): void
    {
        parent::setUp();

        // Use createStub() instead of getMockBuilder() when you don't need expectations
        $this->adapter = $this->createStub(VaultAdapterInterface::class);

        $this->manager = $this->getMockBuilder(KeyManagerInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(KeyManager::class))
            ->getMock();

        $this->auth = $this->getMockBuilder(KeyInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(Key::class))
            ->getMock();
    }

    public function testRotateSecretsKeyRotationOnly(): void
    {
        $manager = $this->getManager();
        
        // Mock the key manager's rotateKeys method
        $this->manager->expects($this->once())
            ->method('rotateKeys')
            ->with('test_vault', ['kms_key'])
            ->willReturn(true);

        // Mock the key manager's unlockKeyring method
        $this->manager->expects($this->once())
            ->method('unlockKeyring')
            ->with($this->auth);

        // Mock the key manager's saveKeyring method
        $this->manager->expects($this->once())
            ->method('saveKeyring')
            ->with($this->auth);

        $result = $manager->rotateSecrets('test_vault');
        $this->assertTrue($result);
    }

    protected function setupMethodConfigureSharedOptions(int $times = 1): void
    {
        // If you need this method, configure the stub to return values
        $this->adapter->method('configureSharedOptions')
            ->willReturnCallback(function ($resolver) {
                $resolver->setIgnoreUndefined(true);
                $resolver->define('vault');
            });
    }

    protected function getDefaultOptions(): array
    {
        return ['vault' => 'test_vault'];
    }

    protected function getManager(): SecretManagerInterface
    {
        $this->auth->expects($this->once())
            ->method('getType')
            ->willReturn(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);
            
        $this->manager->expects($this->once())
            ->method('loadKeyring');

        return new SecretManager($this->adapter, $this->manager, $this->auth, 'test_vault');
    }
}
