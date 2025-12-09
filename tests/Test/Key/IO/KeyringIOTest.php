<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key\IO;

use ParadiseSecurity\Component\SecretsManager\Exception\KeyringIOException;
use ParadiseSecurity\Component\SecretsManager\Adapter\Filesystem\FilesystemAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\IO\KeyringIO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyringIO::class)]
final class KeyringIOTest extends TestCase
{
    #[Test]
    public function it_checks_if_keyring_exists(): void
    {
        $keyringFilesystem = $this->createStub(FilesystemAdapterInterface::class);

        $filesystemManager = $this->createMock(FilesystemManagerInterface::class);
        $filesystemManager
            ->expects($this->once())
            ->method('getFilesystem')
            ->with(FilesystemManagerInterface::KEYRING, 'test-keyring.keyring')
            ->willReturn($keyringFilesystem);

        $filesystemManager
            ->expects($this->once())
            ->method('getPath')
            ->with('test-keyring.keyring')
            ->willReturn('test-keyring.keyring');

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $this->assertTrue($keyringIO->keyringExists());
    }

    #[Test]
    public function it_returns_false_when_keyring_does_not_exist(): void
    {
        $filesystemManager = $this->createStub(FilesystemManagerInterface::class);
        $filesystemManager
            ->method('getFilesystem')
            ->willThrowException(new \RuntimeException('Not found'));

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $this->assertFalse($keyringIO->keyringExists());
    }

    #[Test]
    public function it_reads_keyring_data_successfully(): void
    {
        $expectedData = 'encrypted-keyring-data';

        $keyringFilesystem = $this->createMock(FilesystemAdapterInterface::class);
        $keyringFilesystem
            ->expects($this->once())
            ->method('read')
            ->with('test-keyring.keyring')
            ->willReturn($expectedData);

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $keyringFilesystem,
                'getPath' => 'test-keyring.keyring',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $result = $keyringIO->readKeyringData();

        $this->assertSame($expectedData, $result);
    }

    #[Test]
    public function it_throws_exception_when_reading_keyring_fails(): void
    {
        $keyringFilesystem = $this->createStub(FilesystemAdapterInterface::class);
        $keyringFilesystem
            ->method('read')
            ->willThrowException(new \RuntimeException('Read failed'));

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $keyringFilesystem,
                'getPath' => 'test-keyring.keyring',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $this->expectException(KeyringIOException::class);
        $this->expectExceptionMessage("Failed to read keyring 'test-keyring'");

        $keyringIO->readKeyringData();
    }

    #[Test]
    public function it_writes_keyring_data_successfully(): void
    {
        $dataToWrite = 'encrypted-keyring-data';

        $keyringFilesystem = $this->createMock(FilesystemAdapterInterface::class);
        $keyringFilesystem
            ->expects($this->once())
            ->method('save')
            ->with('test-keyring.keyring', $dataToWrite);

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $keyringFilesystem,
                'getPath' => 'test-keyring.keyring',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $keyringIO->writeKeyringData($dataToWrite);
    }

    #[Test]
    public function it_throws_exception_when_writing_keyring_fails(): void
    {
        $keyringFilesystem = $this->createStub(FilesystemAdapterInterface::class);
        $keyringFilesystem
            ->method('save')
            ->willThrowException(new \RuntimeException('Write failed'));

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $keyringFilesystem,
                'getPath' => 'test-keyring.keyring',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $this->expectException(KeyringIOException::class);
        $this->expectExceptionMessage("Failed to write keyring 'test-keyring'");

        $keyringIO->writeKeyringData('data');
    }

    #[Test]
    public function it_reads_checksum_data_successfully(): void
    {
        $expectedChecksum = 'checksum-data-here';

        $checksumFilesystem = $this->createMock(FilesystemAdapterInterface::class);
        $checksumFilesystem
            ->expects($this->once())
            ->method('read')
            ->with('test-keyring.checksum')
            ->willReturn($expectedChecksum);

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $checksumFilesystem,
                'getPath' => 'test-keyring.checksum',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $result = $keyringIO->readChecksumData();

        $this->assertSame($expectedChecksum, $result);
    }

    #[Test]
    public function it_throws_exception_when_reading_checksum_fails(): void
    {
        $checksumFilesystem = $this->createStub(FilesystemAdapterInterface::class);
        $checksumFilesystem
            ->method('read')
            ->willThrowException(new \RuntimeException('Read failed'));

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $checksumFilesystem,
                'getPath' => 'test-keyring.checksum',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $this->expectException(KeyringIOException::class);
        $this->expectExceptionMessage("Failed to read checksum for 'test-keyring'");

        $keyringIO->readChecksumData();
    }

    #[Test]
    public function it_writes_checksum_data_successfully(): void
    {
        $checksumData = 'checksum-and-signature';

        $checksumFilesystem = $this->createMock(FilesystemAdapterInterface::class);
        $checksumFilesystem
            ->expects($this->once())
            ->method('save')
            ->with('test-keyring.checksum', $checksumData);

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $checksumFilesystem,
                'getPath' => 'test-keyring.checksum',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $keyringIO->writeChecksumData($checksumData);
    }

    #[Test]
    public function it_throws_exception_when_writing_checksum_fails(): void
    {
        $checksumFilesystem = $this->createStub(FilesystemAdapterInterface::class);
        $checksumFilesystem
            ->method('save')
            ->willThrowException(new \RuntimeException('Write failed'));

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $checksumFilesystem,
                'getPath' => 'test-keyring.checksum',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $this->expectException(KeyringIOException::class);
        $this->expectExceptionMessage("Failed to write checksum for 'test-keyring'");

        $keyringIO->writeChecksumData('data');
    }

    #[Test]
    public function it_opens_keyring_for_reading(): void
    {
        $handle = fopen('php://memory', 'r');

        $keyringFilesystem = $this->createMock(FilesystemAdapterInterface::class);
        $keyringFilesystem
            ->expects($this->once())
            ->method('open')
            ->with('test-keyring.keyring')
            ->willReturn($handle);

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $keyringFilesystem,
                'getPath' => 'test-keyring.keyring',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $result = $keyringIO->openKeyringForReading();

        $this->assertSame($handle, $result);

        fclose($handle);
    }

    #[Test]
    public function it_throws_exception_when_opening_keyring_fails(): void
    {
        $keyringFilesystem = $this->createStub(FilesystemAdapterInterface::class);
        $keyringFilesystem
            ->method('open')
            ->willThrowException(new \RuntimeException('Open failed'));

        $filesystemManager = $this->createConfiguredStub(
            FilesystemManagerInterface::class,
            [
                'getFilesystem' => $keyringFilesystem,
                'getPath' => 'test-keyring.keyring',
            ]
        );

        $keyringIO = new KeyringIO($filesystemManager, 'test-keyring');

        $this->expectException(KeyringIOException::class);
        $this->expectExceptionMessage("Failed to open keyring 'test-keyring' for reading");

        $keyringIO->openKeyringForReading();
    }
}
