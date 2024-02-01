<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Console\Command;

use ParadiseSecurity\Component\SecretsManager\Installer\Checker\CommandDirectoryChecker;
use ParadiseSecurity\Component\SecretsManager\Installer\Setup\Setup;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;

use function sprintf;

use const SECRETS_MANAGER_ROOT;

abstract class AbstractSetupCommand extends Command
{
    public const DIRECTORY_CONFIG = 'config';

    public const DIRECTORY_PACKAGE = 'secrets-manager';

    public const DIRECTORY_KEYRING = 'keyring';

    public const DIRECTORY_SECRETS = 'secrets';

    public const DIRECTORY_MASTER_KEYS = 'master-keys';

    protected ?Setup $setup = null;

    protected string $environment = 'test';

    public function __construct(?string $name = null)
    {
        $this->setup = new Setup();
        parent::__construct($name);
    }

    protected function getRealPath(string $path, string $directory): string
    {
        return $path . DIRECTORY_SEPARATOR . $directory;
    }

    protected function getRootDirectoryPath(): string
    {
        return SECRETS_MANAGER_ROOT;
    }

    protected function askYesOrNoQuestion(
        InputInterface $input,
        OutputInterface $output,
        string $ask
    ): bool {
        $helper = $this->getHelper('question');
        $question = new ConfirmationQuestion(sprintf('%s? (y/N)', $ask), false);
        return $helper->ask($input, $output, $question);
    }

    protected function directoryStructure(): array
    {
        $config = self::DIRECTORY_CONFIG;
        $package = $this->getRealPath($config, self::DIRECTORY_PACKAGE);
        $environment = $this->getRealPath($package, $this->environment);
        $keyring = $this->getRealPath($environment, self::DIRECTORY_KEYRING);
        $keys = $this->getRealPath($environment, self::DIRECTORY_MASTER_KEYS);
        $secrets = $this->getRealPath($environment, self::DIRECTORY_SECRETS);

        return [
            $config,
            $package,
            $environment,
            $keyring,
            $keys,
            $secrets,
        ];
    }

    protected function ensureDirectoryExistsAndIsWritable(
        string $path,
        string $directory,
        OutputInterface $output
    ): void {
        $filesystem = $this->setup->get('filesystem_adapter')->setup($path);

        $checker = new CommandDirectoryChecker($filesystem);
        $checker->setCommandName($this->getName());

        $checker->ensureDirectoryExists($directory, $output);
        $checker->ensureDirectoryIsWritable($directory, $output);
    }
}
