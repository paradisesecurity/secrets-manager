<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;

/**
 * Interactive installer for secrets manager.
 * Guides users through the complete setup process.
 */
final class InstallCommand extends Command
{
    protected static $defaultName = 'secrets:install';
    protected static $defaultDescription = 'Interactive installer for secrets manager';

    protected function configure(): void
    {
        $this
            ->addOption('non-interactive', 'n', InputOption::VALUE_NONE, 'Run in non-interactive mode with defaults')
            ->setHelp(<<<'HELP'
The <info>secrets:install</info> command provides an interactive installation wizard.

<info>php bin/secrets-manager secrets:install</info>

Non-interactive mode (uses defaults):
<info>php bin/secrets-manager secrets:install --non-interactive</info>

HELP
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $io->title('Secrets Manager Interactive Installer');
        $io->text([
            'This wizard will guide you through the setup process.',
            'You can press Ctrl+C at any time to cancel.',
        ]);

        if (!$input->getOption('non-interactive')) {
            $io->newLine();
            $continue = $io->confirm('Continue with installation?', true);
            if (!$continue) {
                $io->comment('Installation cancelled.');
                return Command::SUCCESS;
            }
        }

        try {
            // Step 1: Gather configuration
            $config = $this->gatherConfiguration($input, $io);

            // Step 2: Display configuration summary
            $this->displayConfigurationSummary($io, $config);

            if (!$input->getOption('non-interactive')) {
                $proceed = $io->confirm('Proceed with this configuration?', true);
                if (!$proceed) {
                    $io->comment('Installation cancelled.');
                    return Command::SUCCESS;
                }
            }

            // Step 3: Run setup command with gathered configuration
            $setupExitCode = $this->runSetup($input, $output, $config);

            if ($setupExitCode !== Command::SUCCESS) {
                return $setupExitCode;
            }

            // Step 4: Post-installation steps
            $this->postInstallation($io, $config);

            $io->success([
                'Installation completed successfully!',
                'Your secrets manager is ready to use.',
            ]);

            return Command::SUCCESS;

        } catch (\Exception $e) {
            $io->error('Installation failed: ' . $e->getMessage());
            if ($output->isVerbose()) {
                $io->block($e->getTraceAsString(), null, 'fg=red');
            }
            return Command::FAILURE;
        }
    }

    private function gatherConfiguration(InputInterface $input, SymfonyStyle $io): array
    {
        $config = [];
        $helper = $this->getHelper('question');

        if ($input->getOption('non-interactive')) {
            return $this->getDefaultConfiguration();
        }

        // Paths configuration
        $io->section('1. Path Configuration');

        $rootPath = $this->detectRootPath();
        $question = new Question("Root path [{$rootPath}]: ", $rootPath);
        $config['root-path'] = $helper->ask($input, $io, $question);

        $defaultPackagePath = $config['root-path'] . '/config/secrets-manager';
        $question = new Question("Package path [{$defaultPackagePath}]: ", $defaultPackagePath);
        $config['package-path'] = $helper->ask($input, $io, $question);

        // Storage configuration
        $io->section('2. Storage Configuration');

        $question = new ChoiceQuestion(
            'Master key storage type:',
            ['env', 'file'],
            'env'
        );
        $config['master-key-storage'] = $helper->ask($input, $io, $question);

        if ($config['master-key-storage'] === 'env') {
            $question = new Question('Environment file name [.env]: ', '.env');
            $config['env-file'] = $helper->ask($input, $io, $question);
        }

        // Keyring configuration
        $io->section('3. Keyring Configuration');

        $question = new Question('Keyring name [default]: ', 'default');
        $config['keyring-name'] = $helper->ask($input, $io, $question);

        // Key generation
        $io->section('4. Key Generation');

        $question = new ConfirmationQuestion(
            'Generate authentication key now? (Recommended) (Y/n): ',
            true
        );
        $config['generate-auth-key'] = $helper->ask($input, $io, $question);

        return $config;
    }

    private function getDefaultConfiguration(): array
    {
        return [
            'root-path' => $this->detectRootPath(),
            'package-path' => $this->detectRootPath() . '/config/secrets-manager',
            'master-key-storage' => 'env',
            'env-file' => '.env',
            'keyring-name' => 'default',
            'generate-auth-key' => true,
        ];
    }

    private function displayConfigurationSummary(SymfonyStyle $io, array $config): void
    {
        $io->section('Configuration Summary');
        $io->table(
            ['Setting', 'Value'],
            [
                ['Root Path', $config['root-path']],
                ['Package Path', $config['package-path']],
                ['Master Key Storage', $config['master-key-storage']],
                ['Environment File', $config['env-file'] ?? 'N/A'],
                ['Keyring Name', $config['keyring-name']],
                ['Generate Auth Key', $config['generate-auth-key'] ? 'Yes' : 'No'],
            ]
        );
    }

    private function runSetup(InputInterface $input, OutputInterface $output, array $config): int
    {
        $setupCommand = $this->getApplication()->find('secrets:setup');

        $setupInput = new ArrayInput([
            'command' => 'secrets:setup',
            '--root-path' => $config['root-path'],
            '--package-path' => $config['package-path'],
            '--master-key-storage' => $config['master-key-storage'],
            '--env-file' => $config['env-file'] ?? '.env',
            '--keyring-name' => $config['keyring-name'],
            '--generate-auth-key' => $config['generate-auth-key'],
        ]);

        return $setupCommand->run($setupInput, $output);
    }

    private function postInstallation(SymfonyStyle $io, array $config): void
    {
        $io->section('Post-Installation Checklist');

        $checklist = [
            'Add sensitive directories to .gitignore',
            'Set file permissions (chmod 600 .env, chmod 700 directories)',
            'Backup your authentication key securely',
            'Review security recommendations in documentation',
            'Test your configuration with a sample secret',
        ];

        $io->listing($checklist);

        $io->note([
            'For production environments:',
            '- Use hardware security modules (HSM) or key management services',
            '- Implement key rotation policies',
            '- Enable audit logging',
            '- Use separate keys per environment',
        ]);
    }

    private function detectRootPath(): string
    {
        if (defined('SECRETS_MANAGER_ROOT')) {
            return SECRETS_MANAGER_ROOT;
        }

        try {
            $reflection = new \ReflectionClass(\Composer\Autoload\ClassLoader::class);
            $vendorDir = dirname($reflection->getFileName(), 2);
            return dirname($vendorDir);
        } catch (\Exception) {
            return getcwd();
        }
    }
}
