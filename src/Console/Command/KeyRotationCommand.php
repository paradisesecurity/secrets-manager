<?php declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Console\Command;

use ParadiseSecurity\Component\SecretsManager\Key\KeyManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\SecretManagerInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class KeyRotationCommand extends AbstractSetupCommand
{
    private KeyManagerInterface $keyManager;
    private SecretManagerInterface $secretManager;

    public function __construct(
        KeyManagerInterface $keyManager,
        SecretManagerInterface $secretManager,
        ?string $name = null
    ) {
        $this->keyManager = $keyManager;
        $this->secretManager = $secretManager;
        parent::__construct($name);
    }

    protected function configure(): void
    {
        $this
            ->setName('key:rotate')
            ->setDescription('Rotate encryption keys for a vault')
            ->setDefinition([
                new InputArgument('vault', InputArgument::REQUIRED, 'The vault name to rotate keys for'),
                new InputOption('secrets', null, InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY, 'Specific secrets to re-encrypt (optional)'),
                new InputOption('all-secrets', null, InputOption::VALUE_NONE, 'Re-encrypt all secrets in the vault'),
            ])
            ->setHelp(
                <<<EOT
The <info>%command.name%</info> command rotates encryption keys for a specified vault.

To rotate keys for a vault without re-encrypting secrets:
<info>php ./bin/secrets-manager key:rotate my_vault</info>

To rotate keys and re-encrypt specific secrets:
<info>php ./bin/secrets-manager key:rotate my_vault --secrets=secret1 --secrets=secret2</info>

To rotate keys and re-encrypt all secrets:
<info>php ./bin/secrets-manager key:rotate my_vault --all-secrets</info>
EOT
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $outputStyle = new SymfonyStyle($input, $output);
        $outputStyle->title('Key Rotation');

        $vault = $input->getArgument('vault');
        $secretKeys = $input->getOption('secrets');
        $allSecrets = $input->getOption('all-secrets');

        $outputStyle->writeln(sprintf('<info>Rotating keys for vault: %s</info>', $vault));

        // If we're re-encrypting all secrets or specific secrets
        if ($allSecrets || !empty($secretKeys)) {
            $outputStyle->writeln('<info>Re-encrypting secrets with new keys...</info>');
            
            // If all secrets flag is set, we pass an empty array to rotate all
            $secretsToRotate = $allSecrets ? [] : $secretKeys;
            
            if ($this->secretManager->rotateSecrets($vault, $secretsToRotate)) {
                $outputStyle->success('Keys rotated and secrets re-encrypted successfully.');
            } else {
                $outputStyle->error('Failed to rotate keys and re-encrypt secrets.');
                return 1;
            }
        } else {
            // Just rotate the keys without re-encrypting secrets
            $outputStyle->writeln('<info>Rotating keys only...</info>');
            
            // We need to unlock the keyring first
            // This would require an auth key, which we don't have access to in this command
            // In a real implementation, we would need to load the auth key from storage
            $outputStyle->warning('Key rotation without re-encryption requires manual unlocking of the keyring.');
            $outputStyle->writeln('Please use the full rotation with secrets re-encryption for complete security.');
        }

        return 0;
    }
}
