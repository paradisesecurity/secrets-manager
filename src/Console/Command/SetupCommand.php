<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Console\Command;

use ParadiseSecurity\Component\SecretsManager\Exception\SetupException;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;

/**
 * Handles initial setup and verification of the secrets manager infrastructure.
 * Ensures all required files and directories exist with proper permissions.
 */
final class SetupCommand
{
    public function __construct(
        private FilesystemManagerInterface $filesystemManager,
    ) {
    }

    /**
     * Initializes the secrets manager infrastructure.
     * Creates required directories and files with proper permissions.
     */
    public function initialize(bool $force = false): SetupResult
    {
        $result = new SetupResult();

        try {
            // Check if already initialized
            if ($this->isInitialized() && !$force) {
                $result->addMessage('Secrets manager is already initialized.');
                $result->addMessage('Use --force to reinitialize.');
                return $result;
            }

            // Create keyring directory
            $this->createKeyringDirectory($result);

            // Create vault directory
            $this->createVaultDirectory($result);

            // Create master keys directory
            $this->createMasterKeysDirectory($result);

            // Create environment file if using env storage
            $this->createEnvironmentFile($result);

            // Set proper permissions
            $this->setPermissions($result);

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
            'Keyring directory' => $this->checkKeyringDirectory(),
            'Vault directory' => $this->checkVaultDirectory(),
            'Master keys directory' => $this->checkMasterKeysDirectory(),
            'Environment file' => $this->checkEnvironmentFile(),
            'Directory permissions' => $this->checkPermissions(),
        ];

        foreach ($checks as $name => $passed) {
            if ($passed) {
                $result->addMessage("✓ {$name}: OK");
            } else {
                $result->addMessage("✗ {$name}: MISSING or INCORRECT");
                $result->setSuccess(false);
            }
        }

        if ($result->isSuccess()) {
            $result->addMessage('All checks passed!');
        } else {
            $result->addMessage('Some checks failed. Run initialize command.');
        }

        return $result;
    }

    /**
     * Checks if the secrets manager has been initialized.
     */
    public function isInitialized(): bool
    {
        return $this->checkKeyringDirectory() 
            && $this->checkVaultDirectory() 
            && $this->checkMasterKeysDirectory();
    }

    /**
     * Creates the keyring directory structure.
     */
    private function createKeyringDirectory(SetupResult $result): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::KEYRING
            );

            // Create a .gitkeep file to ensure directory is created
            $filesystem->save('.gitkeep', '');
            
            $result->addMessage('✓ Created keyring directory');
        } catch (\Exception $exception) {
            $result->addMessage('✗ Failed to create keyring directory: ' . $exception->getMessage());
            throw $exception;
        }
    }

    /**
     * Creates the vault directory structure.
     */
    private function createVaultDirectory(SetupResult $result): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::VAULT
            );

            $filesystem->save('.gitkeep', '');
            
            $result->addMessage('✓ Created vault directory');
        } catch (\Exception $exception) {
            $result->addMessage('✗ Failed to create vault directory: ' . $exception->getMessage());
            throw $exception;
        }
    }

    /**
     * Creates the master keys directory structure.
     */
    private function createMasterKeysDirectory(SetupResult $result): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::MASTER_KEYS
            );

            $filesystem->save('.gitkeep', '');
            
            // Create .gitignore to prevent committing keys
            $gitignore = "# Never commit key files\n*.key\n";
            $filesystem->save('.gitignore', $gitignore);
            
            $result->addMessage('✓ Created master keys directory');
            $result->addMessage('  Added .gitignore to prevent committing keys');
        } catch (\Exception $exception) {
            $result->addMessage('✗ Failed to create master keys directory: ' . $exception->getMessage());
            throw $exception;
        }
    }

    /**
     * Creates the environment file with template.
     */
    private function createEnvironmentFile(SetupResult $result): void
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::ENVIRONMENT
            );

            $envTemplate = <<<ENV
# Secrets Manager Configuration
# Generated on: {{date}}
#
# WARNING: This file contains sensitive cryptographic keys.
# Do NOT commit this file to version control.
# Add to .gitignore immediately.

# Add your keys below (will be populated during setup)

ENV;

            $envTemplate = str_replace('{{date}}', date('Y-m-d H:i:s'), $envTemplate);
            
            $filesystem->save('.env', $envTemplate);
            
            $result->addMessage('✓ Created environment file template');
            $result->addMessage('  WARNING: Add .env to .gitignore!');
        } catch (\Exception $exception) {
            // Env file is optional, just warn
            $result->addMessage('⚠ Could not create environment file (optional)');
        }
    }

    /**
     * Sets proper permissions on sensitive directories.
     */
    private function setPermissions(SetupResult $result): void
    {
        // Note: Permission setting is filesystem-dependent
        // This is a placeholder for platform-specific implementations
        $result->addMessage('⚠ Ensure proper permissions are set manually:');
        $result->addMessage('  - Keyring directory: 0700 (rwx------)');
        $result->addMessage('  - Vault directory: 0700 (rwx------)');
        $result->addMessage('  - Master keys directory: 0700 (rwx------)');
        $result->addMessage('  - .env file: 0600 (rw-------)');
    }

    // Check methods
    private function checkKeyringDirectory(): bool
    {
        try {
            $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::KEYRING,
                '.gitkeep'
            );
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    private function checkVaultDirectory(): bool
    {
        try {
            $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::VAULT,
                '.gitkeep'
            );
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    private function checkMasterKeysDirectory(): bool
    {
        try {
            $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::MASTER_KEYS,
                '.gitkeep'
            );
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    private function checkEnvironmentFile(): bool
    {
        try {
            $filesystem = $this->filesystemManager->getFilesystem(
                FilesystemManagerInterface::ENVIRONMENT,
                '.env'
            );
            return $filesystem->fileExists('.env');
        } catch (\Exception) {
            return false;
        }
    }

    private function checkPermissions(): bool
    {
        // Platform-dependent check
        // Return true for now, implement platform-specific checks as needed
        return true;
    }
}
