<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Storage;

use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;
use Symfony\Component\Dotenv\Dotenv;

use function gettype;
use function is_array;
use function is_object;
use function is_string;
use function json_decode;
use function json_encode;
use function sprintf;
use function strtoupper;

use const PHP_EOL;

final class EnvironmentBasedKeyStorage implements KeyStorageInterface
{
    private $dotenv;

    private $envFileName;

    public const NAME = 'env';

    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
        string $envFileName = KeyStorageInterface::ENVIRONMENT_FILE_NAME
    ) {
        $this->envFileName = $envFileName;
        $this->dotenv = new Dotenv();
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function import(string $name): mixed
    {
        $name = strtoupper($name);
        if (isset($_ENV[$name])) {
            return null;
        }

        try {
            $filesystem = $this->filesystemManager->getFilesystem(FilesystemManagerInterface::ENVIRONMENT);
            $path = $filesystem->realpath($this->envFileName);

            $this->dotenv->load($path);
            return null;
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException('Unable to import environment key file.', $exception);
        }
    }

    public function save(string $name, KeyInterface $key): void
    {
        $name = strtoupper($name);

        $contents = [
            'hex' => $key->getHex()->getString(),
            'type' => $key->getType(),
            'adapter' => $key->getAdapter(),
            'version' => $key->getVersion(),
        ];
        $contents = json_encode($contents);

        $env = [];
        try {
            $filesystem = $this->filesystemManager->getFilesystem(FilesystemManagerInterface::ENVIRONMENT, $this->envFileName);
            $env = $this->getPreviousEnvironment($filesystem);
        } catch (FilesystemNotFoundException $exception) {
            $filesystem = $this->filesystemManager->getFilesystem(FilesystemManagerInterface::ENVIRONMENT);
        }
        $env[$name] = $contents;

        $newEnv = '';
        foreach ($env as $index => $value) {
            $newEnv = $newEnv . $index . "='" . $value . "'" . PHP_EOL;
        }

        try {
            $filesystem->save($this->envFileName, $newEnv);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToLoadKeyException('Unable to save env file.', $exception);
        }
    }

    public function resolve(string $contents): KeyInterface
    {
        $name = strtoupper($contents);
        if (!isset($_ENV[$name])) {
            throw new UnableToLoadKeyException('Unable to resolve env variable into key.');
        }

        $contents = $_ENV[$name];

        if (is_string($contents)) {
            $contents = json_decode($contents, true);
        }

        if (is_object($contents)) {
            $contents = (array) $contents;
        }

        if (!is_array($contents)) {
            throw new UnableToLoadKeyException(sprintf('Unable to resolve environment variable of type "%s".', gettype($contents)));
        }

        $hex = $contents['hex'];
        $type = $contents['type'];
        $adapter = $contents['adapter'];
        $version = $contents['version'];

        return new Key(new HiddenString($hex), $type, $adapter, $version);
    }

    private function getPreviousEnvironment(FilesystemAdapterInterface $filesystem): array
    {
        try {
            $data = $filesystem->read($this->envFileName);
            return $this->dotenv->parse($data);
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException('Unable to load previous env file.', $exception);
        }
    }
}
