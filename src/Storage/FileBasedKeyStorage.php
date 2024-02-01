<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Storage;

use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

use function explode;
use function is_array;

use const PHP_EOL;

final class FileBasedKeyStorage implements KeyStorageInterface
{
    private $keyFileExt;

    public const NAME = 'file';

    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
        string $keyFileExt = KeyStorageInterface::KEY_FILE_EXTENSION
    ) {
        $this->keyFileExt = $keyFileExt;
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function import(string $name): mixed
    {
        $filename = $this->getFilename($name);

        try {
            $filesystem = $this->filesystemManager->getFilesystem(FilesystemManagerInterface::MASTER_KEYS, $filename);
        } catch (FilesystemNotFoundException $exception) {
            return null;
        }

        try {
            return $filesystem->read($filename);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToLoadKeyException('Unable to import key file.', $exception);
        }
    }

    public function save(string $name, KeyInterface $key): void
    {
        $filename = $this->getFilename($name);

        $hex = $key->getHex()->getString() . PHP_EOL;
        $type = $key->getType() . PHP_EOL;
        $adapter = $key->getAdapter() . PHP_EOL;
        $version = $key->getVersion();

        $contents = $hex.=$type.=$adapter.=$version;

        $filesystem = $this->filesystemManager->getFilesystem(FilesystemManagerInterface::MASTER_KEYS);

        try {
            $filesystem->save($filename, $contents);
        } catch (FilesystemErrorException $exception) {
            throw new UnableToLoadKeyException('Unable to save key file.', $exception);
        }
    }

    public function resolve(string $contents): KeyInterface
    {
        //$lines = preg_split('/\r\n|\r|\n/', $fc);
        $data = explode(PHP_EOL, $contents, 4);

        if (!is_array($data)) {
            throw new UnableToLoadKeyException('Unable to resolve file data into key.');
        }

        if (count($data) !== 4) {
            throw new UnableToLoadKeyException('Unable to resolve file data into key.');
        }

        $hex = $data[0];
        $type = $data[1];
        $adapter = $data[2];
        $version = $data[3];

        return new Key(new HiddenString($hex), $type, $adapter, $version);
    }

    private function getFilename(string $name): string
    {
        return $this->filesystemManager->getPath(
            $name . $this->keyFileExt
        );
    }
}
