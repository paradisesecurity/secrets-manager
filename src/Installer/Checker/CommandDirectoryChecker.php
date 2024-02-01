<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Checker;

use ParadiseSecurity\Component\SecretsManager\Exception\FilesystemErrorException;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemAdapterInterface;
use Symfony\Component\Console\Output\OutputInterface;

use function sprintf;

final class CommandDirectoryChecker
{
    private ?string $name = null;

    public function __construct(private FilesystemAdapterInterface $filesystem)
    {
    }

    public function ensureDirectoryExists($directory, OutputInterface $output): void
    {
        if ($this->filesystem->has($directory)) {
            return;
        }

        try {
            $this->filesystem->mkdir($directory, ['visibility' => 'public']);

            $output->writeln(sprintf('Created "%s" directory.', $this->filesystem->realpath($directory)));
        } catch (FilesystemErrorException) {
            $output->writeln('');
            $output->writeln('<error>Cannot run command due to unexisting directory (tried to create it automatically, failed).</error>');
            $output->writeln('');

            throw new \RuntimeException(sprintf(
                'Create directory "%s" and run command "%s"',
                $this->filesystem->realpath($directory),
                $this->name,
            ));
        }
    }

    public function ensureDirectoryIsWritable($directory, OutputInterface $output): void
    {
        if ($this->filesystem->permission($directory, 'public')) {
            return;
        }

        try {
            $this->filesystem->chmod($directory, 'public');

            $output->writeln(sprintf('Changed "%s" permissions to 0750.', $this->filesystem->realpath($directory)));
        } catch (FilesystemErrorException) {
            $output->writeln('');
            $output->writeln('<error>Cannot run command due to bad directory permissions (tried to change permissions to 0750).</error>');
            $output->writeln('');

            throw new \RuntimeException(sprintf(
                'Set "%s" writable and run command "%s"',
                $this->filesystem->realpath($directory),
                $this->name,
            ));
        }
    }

    public function setCommandName(string $name): void
    {
        $this->name = $name;
    }
}
