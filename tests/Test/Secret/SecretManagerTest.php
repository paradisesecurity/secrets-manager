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
use ParadiseSecurity\Component\SecretsManager\Secret\ChainVaultAdapter;
use ParadiseSecurity\Component\SecretsManager\Secret\Secret;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManager;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\VaultAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Test\MockTrait;
use ParagonIE\HiddenString\HiddenString;

use function array_merge;
use function hex2bin;

final class SecretManagerTest extends TestCase
{
    use MockTrait;

    private $adapter;

    private $manager;

    private $auth;

    protected function setUp(): void
    {
        parent::setUp();

        $this->adapter = $this->getMockBuilder(VaultAdapterInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(ChainVaultAdapter::class))
            ->getMock();
        $this->manager = $this->getMockBuilder(KeyManagerInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(KeyManager::class))
            ->getMock();
        $this->auth = $this->getMockBuilder(KeyInterface::class)
            ->disableOriginalConstructor()
            ->onlyMethods($this->getClassMethods(Key::class))
            ->getMock();
    }

    public function testConstruct(): void
    {
        $manager = $this->getManager();

        $this->assertInstanceOf(SecretManagerInterface::class, $manager);
    }

    public function testGetSecret(): void
    {
        $secret  = $this->getSecret();
        $manager = $this->getManager();

        $this->setupMethodGetMetadata();

        $this->setupMethodConfigureSharedOptions();
        $this->setupMethodConfigureGetSecretOptions();
        $this->adapter->expects($this->exactly(1))
            ->method('getSecret')
            ->with($this->getSHMKey(), $this->getDefaultOptions())
            ->willReturn($secret);

        $result = $manager->getSecret('api_key', $this->getDefaultOptions());
        $this->assertInstanceOf(SecretInterface::class, $result);
        $this->assertEquals($secret, $result);
    }

    public function testGetBadSecret(): void
    {
        $error = 'No secret was found for: "xk0QTphu7nxHfghl10zOng==".';
        $this->expectException(SecretNotFoundException::class);
        $this->expectExceptionMessage($error);

        $manager = $this->getManager();

        $this->setupMethodGetMetadata();

        $this->setupMethodConfigureSharedOptions();
        $this->setupMethodConfigureGetSecretOptions();
        $this->adapter->expects($this->exactly(1))
            ->method('getSecret')
            ->with('xk0QTphu7nxHfghl10zOng==', $this->getDefaultOptions())
            ->will($this->throwException(new SecretNotFoundException($error)));

        $manager->getSecret('aws_secret_key', $this->getDefaultOptions());
    }

    public function testPutSecret(): void
    {
        $secret  = $this->getSecret();
        $manager = $this->getManager();

        $this->setupMethodConfigureSharedOptions();
        $this->adapter->expects($this->exactly(1))
            ->method('configurePutSecretOptions');
        $this->adapter->expects($this->exactly(1))
            ->method('putSecret')
            ->with($secret, $this->getDefaultOptions())
            ->willReturn($secret);

        $response = $manager->putSecret($secret, $this->getDefaultOptions());
        $this->assertEquals($secret, $response);
    }

    public function testDeleteSecretByKey(): void
    {
        $secret  = $this->getSecret();
        $manager = $this->getManager();

        $this->setupMethodGetMetadata();

        $this->setupMethodConfigureSharedOptions(2);
        $this->setupMethodConfigureGetSecretOptions();
        $this->adapter->expects($this->exactly(1))
            ->method('getSecret')
            ->with($this->getSHMKey(), $this->getDefaultOptions())
            ->willReturn($secret);
        $this->adapter->expects($this->exactly(1))
            ->method('configureDeleteSecretOptions');
        $this->adapter->expects($this->exactly(1))
            ->method('deleteSecret')
            ->with($secret, $this->getDefaultOptions());

        $manager->deleteSecretByKey('api_key', $this->getDefaultOptions());
    }

    public function testDeleteSecret(): void
    {
        $secret  = $this->getSecret();
        $manager = $this->getManager();

        $this->setupMethodConfigureSharedOptions();
        $this->adapter->expects($this->exactly(1))
            ->method('configureDeleteSecretOptions');
        $this->adapter->expects($this->exactly(1))
            ->method('deleteSecret')
            ->with($secret, $this->getDefaultOptions());

        $manager->deleteSecret($secret, $this->getDefaultOptions());
    }

    public function testGetVaultAdapter(): void
    {
        $manager = $this->getManager();

        $this->assertEquals($this->adapter, $manager->getVaultAdapter());
        $this->assertInstanceOf(VaultAdapterInterface::class, $manager->getVaultAdapter());
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
        $secret  = $this->getSecret();
        $manager = $this->getManager();

        $this->setupMethodGetMetadata();

        $this->setupMethodConfigureSharedOptions();
        $this->setupMethodConfigureGetSecretOptions();
        $this->adapter->expects($this->exactly(1))
            ->method('getSecret')
            ->with($this->getSHMKey(), $this->getDefaultOptions())
            ->willReturn($secret);

        $value = $manager->vault('classified')->get('api_key');
        $this->assertEquals('secret_value', $value);
    }

    public function testNewVault(): void
    {
        $manager = $this->getManager();

        $kmsKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY);
        $cacheKeyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);

        $key = clone $this->auth;

        $this->manager->expects($this->exactly(1))
            ->method('unlockKeyring')
            ->with($this->auth);
        $this->manager->expects($this->exactly(1))
            ->method('hasVault')
            ->with('irs_secrets')
            ->willReturn(false);
        $this->manager->expects($this->exactly(2))
            ->method('newKey')
            ->withConsecutive(
                ['irs_secrets', 'kms_key', $kmsKeyConfig],
                ['irs_secrets', 'cache_key', $cacheKeyConfig]
            )
            ->willReturnOnConsecutiveCalls($key, $key);
        $this->manager->expects($this->exactly(1))
            ->method('getRawKeyMaterial')
            ->with($key)
            ->willReturn(new HiddenString(
                hex2bin('9f7fc445a91f3322674b2c63f29f2ba6e40848065f4d88c98213d355048daecc')
            ));
        $this->manager->expects($this->exactly(2))
            ->method('addMetadata')
            ->withConsecutive(
                ['irs_secrets', 'cache_key_l', hex2bin('9f7fc445a91f3322674b2c63f29f2ba6')],
                ['irs_secrets', 'cache_key_r', hex2bin('e40848065f4d88c98213d355048daecc')]
            );
        $this->manager->expects($this->exactly(1))
            ->method('saveKeyring')
            ->with($this->auth);

        $manager->newVault('irs_secrets');
    }

    public function testDeleteVault(): void
    {
        $manager = $this->getManager();

        $this->setupMethodConfigureSharedOptions();
        $this->adapter->expects($this->exactly(1))
            ->method('configureDeleteSecretOptions')
            ->will(
                $this->returnCallback(function ($resolver) {
                    $resolver->define('delete_all')->default(false);
                })
            );
        $this->adapter->expects($this->exactly(1))
            ->method('deleteVault')
            ->with(array_merge($this->getDefaultOptions(), ['delete_all' => true]));

        $this->manager->expects($this->exactly(1))
            ->method('unlockKeyring')
            ->with($this->auth);
        $this->manager->expects($this->exactly(1))
            ->method('flushVault')
            ->with('classified');
        $this->manager->expects($this->exactly(1))
            ->method('saveKeyring')
            ->with($this->auth);

        $manager->deleteVault('classified');
    }

    protected function setupMethodConfigureGetSecretOptions(): void
    {
        $this->adapter->expects($this->exactly(1))
            ->method('configureGetSecretOptions');
    }

    protected function setupMethodGetMetadata(): void
    {
        $this->manager->expects($this->exactly(2))
            ->method('getMetadata')
            ->withConsecutive(
                ['classified', 'cache_key_l'],
                ['classified', 'cache_key_r']
            )
            ->willReturnOnConsecutiveCalls(
                hex2bin('9f7fc445a91f3322674b2c63f29f2ba6'),
                hex2bin('e40848065f4d88c98213d355048daecc')
            );
    }

    protected function setupMethodConfigureSharedOptions(int $times = 1): void
    {
        $this->adapter->expects($this->exactly($times))
            ->method('configureSharedOptions')
            ->will(
                $this->returnCallback(function ($resolver) {
                    $resolver->setIgnoreUndefined(true);
                    $resolver->define('vault');
                })
            );
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
        $this->auth->expects($this->exactly(1))
            ->method('getType')
            ->willReturn(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);

        $this->manager->expects($this->exactly(1))
            ->method('loadKeyring');

        return new SecretManager($this->adapter, $this->manager, $this->auth);
    }
}
