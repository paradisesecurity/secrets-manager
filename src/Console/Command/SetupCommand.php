<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Console\Command;

use ParadiseSecurity\Component\SecretsManager\Builder\EncryptionBuilder;
use ParadiseSecurity\Component\SecretsManager\Builder\StorageBuilder;
use ParadiseSecurity\Component\SecretsManager\Exception\SetupException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfig;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Storage\Serialization\KeySerializer;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\ChoiceQuestion;

/**
 * Handles initial setup and verification of the secrets manager infrastructure.
 */
final class SetupCommand extends Command
{
    protected static $defaultName = 'secrets:setup';
    protected static $defaultDescription = 'Initialize and configure the secrets manager';

    private FilesystemManagerInterface $filesystemManager;
    private ?KeyFactoryInterface $keyFactory = null;
    private ?KeySerializer $keySerializer = null;

    public function __construct(?FilesystemManagerInterface $filesystemManager = null)
    {
        parent::__construct();
        
        if ($filesystemManager !== null) {
            $this->filesystemManager = $filesystemManager;
        }
    }

    protected function configure(): void
    {
        $this
            ->addOption('verify', null, InputOption::VALUE_NONE, 'Verify existing setup without making changes')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Force re-initialization even if already setup')
            ->addOption('root-path', null, InputOption::VALUE_REQUIRED, 'Root path for the application')
            ->addOption('package-path', null, InputOption::VALUE_REQUIRED, 'Package configuration path')
            ->addOption('master-key-storage', null, InputOption::VALUE_REQUIRED, 'Master key storage type (env|file)', 'env')
            ->addOption('env-file', null, InputOption::VALUE_REQUIRED, 'Environment file name', '.env')
            ->addOption('keyring-name', null, InputOption::VALUE_REQUIRED, 'Keyring name', 'default')
            ->addOption('generate-auth-key', null, InputOption::VALUE_NONE, 'Generate authentication key during setup')
            ->setHelp(<<<'HELP'
The <info>secrets:setup</info> command initializes the secrets manager infrastructure.

<info>php bin/secrets-manager secrets:setup</info>

Verify existing setup:
<info>php bin/secrets-manager secrets:setup --verify</info>

Force re-initialization:
<info>php bin/secrets-manager secrets:setup --force</info>

Specify custom paths:
<info>php bin/secrets-manager secrets:setup --root-path=/path/to/root --package-path=/path/to/config</info>

HELP
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Secrets Manager Setup');

        try {
            // Initialize dependencies if not already set
            if (!isset($this->filesystemManager)) {
                $this->initializeFromOptions($input, $io);
            }

            // Handle verify mode
            if ($input->getOption('verify')) {
                return $this->handleVerify($io);
            }

            // Handle initialization
            return $this->handleInitialize($input, $io);

        } catch (\Exception $e) {
            $io->error('Setup failed: ' . $e->getMessage());
            if ($output->isVerbose()) {
                $io->block($e->getTraceAsString(), null, 'fg=red');
            }
            return Command::FAILURE;
        }
    }

    private function initializeFromOptions(InputInterface $input, SymfonyStyle $io): void
    {
        $rootPath = $input->getOption('root-path');
        $packagePath = $input->getOption('package-path');

        if (!$rootPath) {
            $rootPath = $this->detectRootPath();
        }

        if (!$packagePath) {
            $packagePath = $rootPath . '/config/secrets-manager';
        }

        $io->section('Configuration');
        $io->listing([
            "Root path: {$rootPath}",
            "Package path: {$packagePath}",
            "Master key storage: " . $input->getOption('master-key-storage'),
            "Environment file: " . $input->getOption('env-file'),
        ]);

        // Build filesystem manager
        $storageBuilder = new StorageBuilder();
        $storageBuilder
            ->withPaths(['root' => $rootPath, 'package' => $packagePath])
            ->useMasterKeyStorage($input->getOption('master-key-storage'))
            ->withEnvFile($input->getOption('env-file'));

        $this->filesystemManager = $storageBuilder->build();

        // Build key factory for key generation
        $encryptionBuilder = new EncryptionBuilder();
        $encryptionBuilder->useAdapter('halite');
        $this->keyFactory = $encryptionBuilder->buildKeyFactory();
        $this->keySerializer = new KeySerializer();
    }

    private function detectRootPath(): string
    {
        if (defined('SECRETS_MANAGER_ROOT')) {
            return SECRETS_MANAGER_ROOT;
        }

        // Try to detect from vendor directory
        $reflection = new \ReflectionClass(\Composer\Autoload\ClassLoader::class);
        $vendorDir = dirname($reflection->getFileName(), 2);
        
        return dirname($vendorDir);
    }

    private function handleVerify(SymfonyStyle $io): int
    {
        $io->section('Verifying Setup');

        $result = $this->verify();

        // Display results
        foreach ($result->getMessages() as $message) {
            $io->writeln($message);
        }

        foreach ($result->getWarnings() as $warning) {
            $io->warning($warning);
        }

        foreach ($result->getErrors() as $error) {
            $io->error($error);
        }

        if ($result->isSuccess()) {
            $io->success('All verification checks passed!');
            return Command::SUCCESS;
        } else {
            $io->error('Some verification checks failed. Run setup without --verify to initialize.');
            return Command::FAILURE;
        }
    }

    private function handleInitialize(InputInterface $input, SymfonyStyle $io): int
    {
        $force = $input->getOption('force');

        // Check if already initialized
        if ($this->isInitialized() && !$force) {
            $io->warning('Secrets manager is already initialized.');
            
            $helper = $this->getHelper('question');
            $question = new ConfirmationQuestion('Do you want to reinitialize? This may overwrite existing configuration. (y/N) ', false);
            
            if (!$helper->ask($input, $output ?? $io, $question)) {
                $io->note('Setup cancelled. Use --force to skip this prompt.');
                return Command::SUCCESS;
            }
            
            $force = true;
        }

        $io->section('Initializing Secrets Manager');

        // Initialize infrastructure
        $result = $this->initializeSecretsManager($force);

        // Display progress
        foreach ($result->getMessages() as $message) {
            $io->writeln($message);
        }

        // Handle authentication key generation if requested
        if ($input->getOption('generate-auth-key')) {
            $io->section('Generating Authentication Key');
            $this->generateAuthenticationKey($io, $input->getOption('master-key-storage'));
        }

        // Display warnings
        if (!empty($result->getWarnings())) {
            $io->warning($result->getWarnings());
        }

        // Final status
        if ($result->isSuccess()) {
            $io->success([
                'Secrets manager initialized successfully!',
                '',
                'Next steps:',
                '1. Add sensitive directories to .gitignore',
                '2. Set proper file permissions (see warnings above)',
                '3. Generate or import your master keys',
                '4. Start using the secrets manager in your application',
            ]);

            // Show example usage
            $this->showExampleUsage($io);

            return Command::SUCCESS;
        } else {
            $io->error('Initialization failed. Check errors above.');
            return Command::FAILURE;
        }
    }

    /**
     * Initializes the secrets manager infrastructure.
     */
    public function initializeSecretsManager(bool $force = false): SetupResult
    {
        $result = new SetupResult();

        try {
            if ($this->isInitialized() && !$force) {
                $result->addMessage('Secrets manager is already initialized.');
                $result->addMessage('Use --force to reinitialize.');
                return $result;
            }

            // Create directory structure
            $this->createDirectoryStructure($result);

            // Create configuration templates
            $this->createConfigurationTemplates($result);

            // Set security recommendations
            $this->addSecurityRecommendations($result);

            $result->setSuccess(true);
            $result->addMessage('✓ Secrets manager initialized successfully!');

            return $result;

        } catch (\Exception $exception) {
            throw new SetupException(
                'Failed to initialize secrets manager: ' . $exception->getMessage(),
                previous: $exception
            );
        }
    }

    /**
     * Verifies that all required infrastructure exists.
     */
    public function verify(): SetupResult
    {
        $result = new SetupResult();

        $checks = [
            'Keyring directory' => $this->checkDirectory(FilesystemManagerInterface::KEYRING),
            'Vault directory' => $this->checkDirectory(FilesystemManagerInterface::VAULT),
            'Master keys directory' => $this->checkDirectory(FilesystemManagerInterface::MASTER_KEYS),
            'Environment file' => $this->checkEnvironmentFile(),
        ];

        $allPassed = true;
        foreach ($checks as $name => $passed) {
            if ($passed) {
                $result->addMessage("✓ {$name}: OK");
            } else {
                $result->addMessage("✗ {$name}: MISSING");
                $allPassed = false;
            }
        }

        $result->setSuccess($allPassed);

        if ($allPassed) {
            $result->addMessage("\n✓ All checks passed!");
        } else {
            $result->addWarning('Some checks failed. Run initialize command to setup.');
        }

        return $result;
    }

    /**
     * Checks if the secrets manager has been initialized.
     */
    public function isInitialized(): bool
    {
        return $this->checkDirectory(FilesystemManagerInterface::KEYRING)
            && $this->checkDirectory(FilesystemManagerInterface::VAULT)
            && $this->checkDirectory(FilesystemManagerInterface::MASTER_KEYS);
    }

    private function createDirectoryStructure(SetupResult $result): void
    {
        // Create keyring directory
        $this->createDirectory(FilesystemManagerInterface::KEYRING, $result, 'keyring');

        // Create vault directory
        $this->createDirectory(FilesystemManagerInterface::VAULT, $result, 'vault');

        // Create master keys directory with security files
        $this->createMasterKeysDirectory($result);
    }

    private function createDirectory(string $type, SetupResult $result, string $name): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem($type);
            $filesystem->save('.gitkeep', '');
            $result->addMessage("✓ Created {$name} directory");
        } catch (\Exception $e) {
            $result->addError("Failed to create {$name} directory: " . $e->getMessage());
            throw $e;
        }
    }

    private function createMasterKeysDirectory(SetupResult $result): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::MASTER_KEYS
            );

            // Create .gitkeep
            $filesystem->save('.gitkeep', '');

            // Create .gitignore to prevent committing keys
            $gitignore = <<<'GITIGNORE'
# Never commit cryptographic key files
*.key
*.keyring
*.pem
*.der

# Allow .gitkeep
!.gitkeep
GITIGNORE;

            $filesystem->save('.gitignore', $gitignore);

            // Create README with security instructions
            $readme = <<<'README'
# Master Keys Directory

⚠️ **SECURITY WARNING** ⚠️

This directory contains cryptographic master keys that protect your secrets.

## Security Guidelines

1. **Never commit keys to version control**
   - All key files are in .gitignore
   - Double-check before committing

2. **Set restrictive permissions**
   ```
   chmod 700 .
   chmod 600 *.key
   ```

3. **Backup keys securely**
   - Store backups in encrypted storage
   - Use hardware security modules (HSM) for production
   - Consider key management services (AWS KMS, Azure Key Vault, etc.)

4. **Rotate keys regularly**
   - Use the key-rotation command
   - Follow your organization's security policies

5. **Limit access**
   - Only authorized personnel should access this directory
   - Use separate keys for different environments

## Key Files
   - `*.key` - Individual cryptographic keys
   - `*.keyring` - Keyring files containing multiple keys

For more information, see the documentation at:
https://github.com/paradisesecurity/secrets-manager

README;

            $filesystem->save('README.md', $readme);

            $result->addMessage('✓ Created master keys directory');
            $result->addMessage('  - Added .gitignore for security');
            $result->addMessage('  - Added README with security guidelines');

        } catch (\Exception $e) {
            $result->addError('Failed to create master keys directory: ' . $e->getMessage());
            throw $e;
        }
    }

    private function createConfigurationTemplates(SetupResult $result): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::ENVIRONMENT
            );

            // Check if .env already exists
            if ($filesystem->fileExists('.env')) {
                $result->addWarning('.env file already exists - skipping template creation');
                return;
            }

            $envTemplate = <<<'ENV'
# Secrets Manager Configuration
# Generated on: {{date}}
#
# ⚠️ WARNING: This file contains sensitive cryptographic keys.
# - Do NOT commit this file to version control
# - Add to .gitignore immediately
# - Set restrictive permissions: chmod 600 .env

# ============================================
# Master Authentication Key
# ============================================
# This key is used to authenticate and encrypt the keyring
# Generate using: php bin/secrets-manager secrets:setup --generate-auth-key
#
# SECRETS_MANAGER_AUTH_KEY=

# ============================================
# Master Encryption Key (Optional)
# ============================================
# Additional encryption key for double encryption
#
# SECRETS_MANAGER_MASTER_KEY=

# ============================================
# Configuration
# ============================================
SECRETS_MANAGER_KEYRING_NAME=default
SECRETS_MANAGER_DEFAULT_VAULT=production

# Encryption adapter (halite is recommended)
SECRETS_MANAGER_ENCRYPTION_ADAPTER=halite

# Storage configuration
SECRETS_MANAGER_MASTER_KEY_STORAGE=env

# Cache configuration (optional)
SECRETS_MANAGER_CACHE_ENABLED=false
SECRETS_MANAGER_CACHE_PREFIX=secrets_

ENV;

            $envTemplate = str_replace('{{date}}', date('Y-m-d H:i:s'), $envTemplate);

            $filesystem->save('.env', $envTemplate);

            // Create .env.example
            $envExample = str_replace(
                ['# SECRETS_MANAGER_AUTH_KEY=', '# SECRETS_MANAGER_MASTER_KEY='],
                ['SECRETS_MANAGER_AUTH_KEY=your_auth_key_here', 'SECRETS_MANAGER_MASTER_KEY=your_master_key_here'],
                $envTemplate
            );

            $filesystem->save('.env.example', $envExample);

            $result->addMessage('✓ Created .env template');
            $result->addMessage('✓ Created .env.example');
            $result->addWarning('Add .env to .gitignore immediately!');

        } catch (\Exception $e) {
            $result->addWarning('Could not create .env template: ' . $e->getMessage());
        }
    }

    private function addSecurityRecommendations(SetupResult $result): void
    {
        $result->addWarning('Security Recommendations:');
        $result->addWarning('  1. Set directory permissions to 0700 (drwx------)');
        $result->addWarning('  2. Set file permissions to 0600 (-rw-------)');
        $result->addWarning('  3. Add sensitive paths to .gitignore');
        $result->addWarning('  4. Enable encryption at rest if available');
        $result->addWarning('  5. Use environment variables or secure vaults for keys');
        $result->addWarning('  6. Implement key rotation policies');
        $result->addWarning('  7. Audit access to key directories regularly');
    }

    private function generateAuthenticationKey(SymfonyStyle $io, string $storageType): void
    {
        try {
            if (!$this->keyFactory) {
                $io->error('Key factory not initialized');
                return;
            }

            // Generate authentication key
            $keyConfig = new KeyConfig(KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY);
            $authKey = $this->keyFactory->generateKey($keyConfig, 'halite');

            // Serialize for storage
            $serialized = $this->keySerializer->serializeToJson($authKey);
            $keyData = json_decode($serialized, true);

            $io->success('Authentication key generated successfully!');
            $io->section('Store this key securely');

            if ($storageType === 'env') {
                $io->block([
                    'Add this line to your .env file:',
                    '',
                    "SECRETS_MANAGER_AUTH_KEY={$keyData['material']}",
                ], null, 'fg=yellow;bg=black', ' ', true);
            } else {
                $io->block([
                    'Save this key to a secure file:',
                    '',
                    $keyData['material'],
                ], null, 'fg=yellow;bg=black', ' ', true);
            }

            $io->warning([
                'SECURITY WARNINGS:',
                '- Never commit this key to version control',
                '- Store backups in a secure location',
                '- Treat this key like a password',
                '- Losing this key means losing access to all secrets',
            ]);

        } catch (\Exception $e) {
            $io->error('Failed to generate authentication key: ' . $e->getMessage());
        }
    }

    private function showExampleUsage(SymfonyStyle $io): void
    {
        $io->section('Example Usage');

        $example = <<<'PHP'
// Build the secrets manager
$authKey = new Key(
new HiddenString($_ENV['SECRETS_MANAGER_AUTH_KEY']),
'symmetric_authentication_key',
'halite',
'5.0.0'
);

$secretsManager = SecretsManagerBuilder::create()
->withAuthKey($authKey)
->withKeyringName('default')
->withDefaultVault('production')
->withPaths($rootPath, $packagePath)
->configureStorage(fn($builder) => 
    $builder
        ->useMasterKeyStorage('env')
        ->withEnvFile('.env')
)
->build();

// Create a vault
$secretsManager->newVault('production');

// Store secrets
$secretsManager->set('database_password', 'super_secret_123');
$secretsManager->set('api_key', 'sk-1234567890');

// Retrieve secrets
$dbPassword = $secretsManager->get('database_password');

PHP;

        $io->block($example, null, 'fg=green', ' ', true);
    }

    private function checkDirectory(string $type): bool
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem($type);
            return $filesystem->fileExists('.gitkeep');
        } catch (\Exception) {
            return false;
        }
    }

    private function checkEnvironmentFile(): bool
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::ENVIRONMENT
            );
            return $filesystem->fileExists('.env') || $filesystem->fileExists('.env.local');
        } catch (\Exception) {
            return false;
        }
    }
}
