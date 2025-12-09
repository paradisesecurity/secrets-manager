<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Secret;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToAccessRestrictedCommandsException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfig;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManager;
use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\ChainVaultAdapter;
use ParadiseSecurity\Component\SecretsManager\Secret\Secret;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManager;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\VaultAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Test\MockTrait;
use ParagonIE\HiddenString\HiddenString;

use function array_merge;
use function hex2bin;

final class SecretManagerTest extends TestCase
{
    use MockTrait;

    protected function setUp(): void
    {
        parent::setUp();
    }

    public function testConstruct(): void
    {
        $manager = $this->getManager();

        $this->assertInstanceOf(SecretManagerInterface::class, $manager);
    }

    public function testGetSecret(): void
    {
        $secret = $this->getSecret();
        
        // Create mocks for both adapter and manager
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $this->setupMethodGetMetadata($manager);
        $this->setupMethodConfigureSharedOptions($adapter);
        $this->setupMethodConfigureGetSecretOptions($adapter);
        
        $adapter->expects($this->once())
            ->method('getSecret')
            ->with($this->getSHMKey(), $this->getDefaultOptions())
            ->willReturn($secret);

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $result = $secretManager->getSecret('api_key', $this->getDefaultOptions());
        $this->assertInstanceOf(SecretInterface::class, $result);
        $this->assertEquals($secret, $result);
    }

    public function testGetBadSecret(): void
    {
        $error = 'No secret was found for: "xk0QTphu7nxHfghl10zOng==".';
        $this->expectException(SecretNotFoundException::class);
        $this->expectExceptionMessage($error);

        $adapter = $this->createMock(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $this->setupMethodGetMetadata($manager);
        $this->setupMethodConfigureSharedOptions($adapter);
        $this->setupMethodConfigureGetSecretOptions($adapter);
        
        $adapter->expects($this->once())
            ->method('getSecret')
            ->with('xk0QTphu7nxHfghl10zOng==', $this->getDefaultOptions())
            ->will($this->throwException(new SecretNotFoundException($error)));

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $secretManager->getSecret('aws_secret_key', $this->getDefaultOptions());
    }

    public function testPutSecret(): void
    {
        $secret = $this->getSecret();
        
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $this->setupMethodConfigureSharedOptions($adapter);
        
        $adapter->expects($this->once())
            ->method('configurePutSecretOptions');
        $adapter->expects($this->once())
            ->method('putSecret')
            ->with($secret, $this->getDefaultOptions())
            ->willReturn($secret);

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $response = $secretManager->putSecret($secret, $this->getDefaultOptions());
        $this->assertEquals($secret, $response);
    }

    public function testDeleteSecretByKey(): void
    {
        $secret = $this->getSecret();
        
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $this->setupMethodGetMetadata($manager);
        $this->setupMethodConfigureSharedOptions($adapter, 2);
        $this->setupMethodConfigureGetSecretOptions($adapter);
        
        $adapter->expects($this->once())
            ->method('getSecret')
            ->with($this->getSHMKey(), $this->getDefaultOptions())
            ->willReturn($secret);
        $adapter->expects($this->once())
            ->method('configureDeleteSecretOptions');
        $adapter->expects($this->once())
            ->method('deleteSecret')
            ->with($secret, $this->getDefaultOptions());

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $secretManager->deleteSecretByKey('api_key', $this->getDefaultOptions());
    }

    public function testDeleteSecret(): void
    {
        $secret = $this->getSecret();
        
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $this->setupMethodConfigureSharedOptions($adapter);
        
        $adapter->expects($this->once())
            ->method('configureDeleteSecretOptions');
        $adapter->expects($this->once())
            ->method('deleteSecret')
            ->with($secret, $this->getDefaultOptions());

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $secretManager->deleteSecret($secret, $this->getDefaultOptions());
    }

    public function testGetVaultAdapter(): void
    {
        $manager = $this->getManager();

        $adapter = $manager->getVaultAdapter();
        $this->assertInstanceOf(VaultAdapterInterface::class, $adapter);
    }

    public function testMissingVaultException(): void
    {
        $error = 'Cannot access secrets without first calling "vault(\'vault_name\')".';
        $this->expectException(UnableToAccessRestrictedCommandsException::class);
        $this->expectExceptionMessage($error);

        $manager = $this->getManager();

        $manager->get('api_key');
    }

    public function testGet(): void
    {
        $secret = $this->getSecret();
        
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $this->setupMethodGetMetadata($manager);
        $this->setupMethodConfigureSharedOptions($adapter);
        $this->setupMethodConfigureGetSecretOptions($adapter);
        
        $adapter->expects($this->once())
            ->method('getSecret')
            ->with($this->getSHMKey(), $this->getDefaultOptions())
            ->willReturn($secret);

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $value = $secretManager->vault('classified')->get('api_key');
        $this->assertEquals('secret_value', $value);
    }

    public function testNewVault(): void
    {
        $adapter = $this->createStub(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $kmsKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $cacheKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);

        $key = $this->createKeyStub();

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $manager->expects($this->once())
            ->method('unlockKeyring')
            ->with($auth);
            
        $manager->expects($this->once())
            ->method('hasVault')
            ->with('irs_secrets')
            ->willReturn(false);

        $newKeyCall = 0;
        $manager
            ->expects($this->exactly(2))
            ->method('newKey')
            ->willReturnCallback(
                function (string $vault, string $name, KeyConfig $config) use (
                    &$newKeyCall,
                    $kmsKeyConfig,
                    $cacheKeyConfig,
                    $key
                ) {
                    $newKeyCall++;

                    if ($newKeyCall === 1) {
                        \PHPUnit\Framework\Assert::assertSame('irs_secrets', $vault);
                        \PHPUnit\Framework\Assert::assertSame('kms_key', $name);
                        \PHPUnit\Framework\Assert::assertEquals($kmsKeyConfig, $config);
                    } elseif ($newKeyCall === 2) {
                        \PHPUnit\Framework\Assert::assertSame('irs_secrets', $vault);
                        \PHPUnit\Framework\Assert::assertSame('cache_key', $name);
                        \PHPUnit\Framework\Assert::assertEquals($cacheKeyConfig, $config);
                    } else {
                        \PHPUnit\Framework\Assert::fail('newKey called more than twice');
                    }

                    return $key;
                }
            );

        $manager->expects($this->once())
            ->method('getRawKeyMaterial')
            ->with($key)
            ->willReturn(new HiddenString(
                hex2bin('9f7fc445a91f3322674b2c63f29f2ba6e40848065f4d88c98213d355048daecc')
            ));

        $addMetadataCall = 0;
        $manager
            ->expects($this->exactly(2))
            ->method('addMetadata')
            ->willReturnCallback(
                function (string $vault, string $name, string $value) use (&$addMetadataCall) {
                    $addMetadataCall++;

                    if ($addMetadataCall === 1) {
                        \PHPUnit\Framework\Assert::assertSame('irs_secrets', $vault);
                        \PHPUnit\Framework\Assert::assertSame('cache_key_l', $name);
                        \PHPUnit\Framework\Assert::assertSame(
                            hex2bin('9f7fc445a91f3322674b2c63f29f2ba6'),
                            $value
                        );
                    } elseif ($addMetadataCall === 2) {
                        \PHPUnit\Framework\Assert::assertSame('irs_secrets', $vault);
                        \PHPUnit\Framework\Assert::assertSame('cache_key_r', $name);
                        \PHPUnit\Framework\Assert::assertSame(
                            hex2bin('e40848065f4d88c98213d355048daecc'),
                            $value
                        );
                    } else {
                        \PHPUnit\Framework\Assert::fail('addMetadata called more than twice');
                    }

                    return null;
                }
            );

        $manager->expects($this->once())
            ->method('saveKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $secretManager->newVault('irs_secrets');
    }

    public function testDeleteVault(): void
    {
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();
        
        $this->setupMethodConfigureSharedOptions($adapter);
        
        $adapter->expects($this->once())
            ->method('configureDeleteSecretOptions')
            ->willReturnCallback(function ($resolver) {
                $resolver->define('delete_all')->default(false);
            });
        $adapter->expects($this->once())
            ->method('deleteVault')
            ->with(array_merge($this->getDefaultOptions(), ['delete_all' => true]));

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        $manager->expects($this->once())
            ->method('unlockKeyring')
            ->with($auth);
            
        $manager->expects($this->once())
            ->method('flushVault')
            ->with('classified');
            
        $manager->expects($this->once())
            ->method('saveKeyring')
            ->with($auth);

        $secretManager = new SecretManager($adapter, $manager, $auth);

        $secretManager->deleteVault('classified');
    }

    protected function setupMethodConfigureGetSecretOptions(VaultAdapterInterface $adapter): void
    {
        $adapter->expects($this->once())
            ->method('configureGetSecretOptions');
    }

    protected function setupMethodGetMetadata(KeyManagerInterface $manager): void
    {
        $call = 0;

        $manager
            ->expects($this->exactly(2))
            ->method('getMetadata')
            ->willReturnCallback(
                function (string $vault, string $name) use (&$call) {
                    $call++;

                    if ($call === 1) {
                        \PHPUnit\Framework\Assert::assertSame('classified', $vault);
                        \PHPUnit\Framework\Assert::assertSame('cache_key_l', $name);

                        return hex2bin('9f7fc445a91f3322674b2c63f29f2ba6');
                    } elseif ($call === 2) {
                        \PHPUnit\Framework\Assert::assertSame('classified', $vault);
                        \PHPUnit\Framework\Assert::assertSame('cache_key_r', $name);

                        return hex2bin('e40848065f4d88c98213d355048daecc');
                    }

                    \PHPUnit\Framework\Assert::fail('getMetadata called more than twice');
                }
            );
    }

    protected function setupMethodConfigureSharedOptions(VaultAdapterInterface $adapter, int $times = 1): void
    {
        $adapter->expects($this->exactly($times))
            ->method('configureSharedOptions')
            ->willReturnCallback(function ($resolver) {
                $resolver->setIgnoreUndefined(true);
                $resolver->define('vault');
            });
    }

    protected function getSHMKey(): string
    {
        return 'ZKZzI3OFpRq3RHY7Btiibg==';
    }

    protected function getDefaultOptions(): array
    {
        return ['vault' => 'classified'];
    }

    protected function getSecret(): SecretInterface
    {
        return new Secret($this->getSHMKey(), 'data_key', 'secret_value');
    }

    protected function getManager(): SecretManagerInterface
    {
        $adapter = $this->createStub(VaultAdapterInterface::class);
        $manager = $this->createMock(KeyManagerInterface::class);
        $auth = $this->createAuthStub();

        $manager->expects($this->once())
            ->method('loadKeyring')
            ->with($auth);

        return new SecretManager($adapter, $manager, $auth);
    }

    /**
     * Create a stub for KeyInterface configured as an authentication key.
     */
    protected function createAuthStub(): KeyInterface
    {
        $auth = $this->createStub(KeyInterface::class);
        $auth->method('getType')
            ->willReturn(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);
        
        return $auth;
    }

    /**
     * Create a stub for a generic KeyInterface.
     */
    protected function createKeyStub(): KeyInterface
    {
        return $this->createStub(KeyInterface::class);
    }
}
