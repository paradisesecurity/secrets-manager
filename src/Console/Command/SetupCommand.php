<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Console\Command;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\HaliteEncryptionAdapter;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Factory\HaliteKeyFactoryAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfig;
use ParadiseSecurity\Component\SecretsManager\Provider\MasterKeyProviderInterface;
use ParadiseSecurity\Component\SecretsManager\Storage\EnvironmentBasedKeyStorage;
use ParadiseSecurity\Component\SecretsManager\Storage\FileBasedKeyStorage;
use ParadiseSecurity\Component\SecretsManager\Storage\KeyStorageInterface;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;

use function strtoupper;
use function sprintf;

use const DIRECTORY_SEPARATOR;

class SetupCommand extends AbstractSetupCommand
{
    private Collection $factoryAdapters;

    private Collection $encryptAdapters;

    private Collection $keyLoaders;

    private FilesystemManagerInterface $filesystemManager;

    public function __construct(?string $name = null)
    {
        parent::__construct($name);
    }

    protected function configure(): void
    {
        $this
            ->setName('setup')
            ->setDescription('Secrets Manager configuration setup.')
            ->setDefinition([
                new InputOption('environment', null, InputOption::VALUE_REQUIRED, 'The working application environment'),
                new InputOption('key-factory', null, InputOption::VALUE_REQUIRED, 'Choose a key factory adapter'),
                new InputOption('encryption', null, InputOption::VALUE_REQUIRED, 'Choose an encryption adapter'),
                new InputOption('key-storage', null, InputOption::VALUE_REQUIRED, 'Choose a key storage method'),
                new InputOption('install-directory', null, InputOption::VALUE_REQUIRED, 'The install directory root path'),
            ])
            ->setHelp(
                <<<EOT
The <info>%command.name%</info> command allows the generation of master encryption keys and default keyring creation.
EOT
            )
        ;

        $this->loadKeyFactoryAdapters();
        $this->loadEncryptionAdapters();
    }

    protected function loadKeyFactoryAdapters(): void
    {
        $this->factoryAdapters = new ArrayCollection();

        $this->factoryAdapters->add(new HaliteKeyFactoryAdapter());
    }

    private function getKeyFactoryAdapters(): array
    {
        $list = [];
        foreach ($this->factoryAdapters as $adapter) {
            $list[] = $adapter->getName();
        }
        return $list;
    }

    protected function loadEncryptionAdapters(): void
    {
        $this->encryptAdapters = new ArrayCollection();

        $provider = $this->setup->get('key_provider')->setup($this->factoryAdapters);

        $this->encryptAdapters->add(new HaliteEncryptionAdapter($provider));
    }

    private function getEncryptionAdapters(): array
    {
        $list = [];
        foreach ($this->encryptAdapters as $adapter) {
            $list[] = $adapter->getName();
        }
        return $list;
    }

    private function getEncryptionAdapter(string $encryption): EncryptionAdapterInterface
    {
        foreach ($this->encryptAdapters as $adapter) {
            if (!($adapter instanceof EncryptionAdapterInterface)) {
                continue;
            }
            if ($adapter->getName() === $encryption) {
                return $adapter;
            }
        }
    }

    protected function loadKeyLoaders(): void
    {
        $this->keyLoaders = new ArrayCollection();

        $env = KeyStorageInterface::ENVIRONMENT_FILE_NAME;
        if ($this->environment === 'test') {
            $env = $env . '.test';
        }

        $this->keyLoaders->add(new EnvironmentBasedKeyStorage(
            $this->filesystemManager,
            $env
        ));
        $this->keyLoaders->add(new FileBasedKeyStorage(
            $this->filesystemManager
        ));
    }

    private function getKeyLoaders(): array
    {
        $list = [];
        foreach ($this->keyLoaders as $loader) {
            $list[] = $loader->getName();
        }
        return $list;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $outputStyle = new SymfonyStyle($input, $output);
        $outputStyle->title('Secrets Manager Setup');

        $environment = $this->setupWorkingEnvironment($input, $output);
        $outputStyle->writeln(sprintf('<info>Environment set to %s.</info>', strtoupper($environment)));
        $this->environment = $environment;

        $factory = $this->setupKeyFactoryAdapter($input, $output);
        $outputStyle->writeln(sprintf('<info>%s key factory will be used to generate keys.</info>', strtoupper($factory)));

        $encryption = $this->setupEncryptionAdapter($input, $output);
        $outputStyle->writeln(sprintf('<info>%s encryption adapter will be used for encryption.</info>', strtoupper($encryption)));

        $this->createDirectoryStructure($input, $outputStyle);
        $this->loadKeyLoaders();

        $outputStyle->section('Encryption Key Setup');

        $storage = $this->setupMasterKeyStorage($input, $output);
        $outputStyle->writeln(sprintf('<info>%s will be used to store your master encryption keys.</info>', \strtoupper($storage)));

        $outputStyle->newLine();

        $keys = $this->askYesOrNoQuestion($input, $output, 'Do you want to generate master encryption keys');
        if ($keys) {
            $overwrite = $this->askYesOrNoQuestion($input, $output, 'Do you want to overwrite existing keys');
            $this->generateMasterKeys($outputStyle, $factory, $storage, $overwrite);
        }

        $outputStyle->newLine();
        $outputStyle->section('Keyring Setup');

        $keyring = $this->askYesOrNoQuestion($input, $output, 'Do you want to setup a keyring');
        if ($keyring) {
            $new = $this->askYesOrNoQuestion($input, $output, 'Do you want to overwrite existing keyring');
            $this->generateKeyring($outputStyle, $environment, $encryption, $storage, $new);
        }

        $outputStyle->newLine();
        //$this->createConfigurationFile($input, $outputStyle);
        $outputStyle->success('Setup complete');

        return 0;
    }

    private function setupWorkingEnvironment(
        InputInterface $input,
        OutputInterface $output
    ): string {
        $helper = $this->getHelper('question');
        if (!$input->getOption('environment')) {
            $question = new ChoiceQuestion('Choose your working environment:', ['dev', 'prod', 'test'], 'test');
            $question->setErrorMessage('Choice %s is invalid.');
            $env = $helper->ask($input, $output, $question);
            $input->setOption('environment', $env);
        }

        return $input->getOption('environment');
    }

    private function setupKeyFactoryAdapter(
        InputInterface $input,
        OutputInterface $output
    ): string {
        $adapters = $this->getKeyFactoryAdapters();
        if (empty($adapters)) {
            throw new \Exception(sprintf('At least one adapter should implement %s', KeyFactoryAdapterInterface::class));
        }

        $helper = $this->getHelper('question');
        if (!$input->getOption('key-factory')) {
            if (count($adapters) === 1) {
                $input->setOption('key-factory', $adapters[0]);
            } else {
                $question = new ChoiceQuestion('Choose your encryption key adapter:', $adapters, 'halite');
                $question->setErrorMessage('Choice %s is invalid.');
                $adapter = $helper->ask($input, $output, $question);
                $input->setOption('key-factory', $adapter);
            }
        }

        return $input->getOption('key-factory');
    }

    private function setupEncryptionAdapter(
        InputInterface $input,
        OutputInterface $output
    ): string {
        $adapters = $this->getEncryptionAdapters();
        if (empty($adapters)) {
            throw new \Exception(sprintf('At least one adapter should implement %s', EncryptionAdapterInterface::class));
        }

        $helper = $this->getHelper('question');
        if (!$input->getOption('encryption')) {
            if (count($adapters) === 1) {
                $input->setOption('encryption', $adapters[0]);
            } else {
                $question = new ChoiceQuestion('Choose your encryption adapter:', $adapters, 'halite');
                $question->setErrorMessage('Choice %s is invalid.');
                $adapter = $helper->ask($input, $output, $question);
                $input->setOption('encryption', $adapter);
            }
        }

        return $input->getOption('encryption');
    }

    private function setupDefaultInstallDirectory(
        InputInterface $input,
        OutputInterface $output,
        string $path,
    ): string {
        if (!$input->getOption('install-directory')) {
            $output->writeln(sprintf('The config directory ( "%s" ) will be installed in the following location', $this->getRealPath(self::DIRECTORY_CONFIG, self::DIRECTORY_PACKAGE)));
            $output->writeln(sprintf('%s', $path));

            $custom = $this->askYesOrNoQuestion($input, $output, 'Do you want change the install location');
            if ($custom) {
                $path = $this->setupCustomInstallDirectory($input, $output);
                $this->setupDefaultInstallDirectory($input, $output, $path);
            }

            $input->setOption('install-directory', $path);
        }

        return $input->getOption('install-directory');
    }

    private function setupCustomInstallDirectory(
        InputInterface $input,
        OutputInterface $output
    ): string {
        $output->note('If this directory does not exist, it will attempt to be created');

        $question = new Question('Enter the full directory path:');
        $question->setValidator(
            function ($value) use ($output): string {
                if (trim($value) === '') {
                    throw new \RuntimeException('The directory path cannot be empty');
                }

                $this->ensureDirectoryExistsAndIsWritable(
                    $value,
                    DIRECTORY_SEPARATOR,
                    $output
                );

                return $value;
            }
        );
        $question->setMaxAttempts(3);
        $helper = $this->getHelper('question');
        return $helper->ask($input, $output, $question);
    }

    private function createDirectoryStructure(
        InputInterface $input,
        OutputInterface $output
    ): void {
        $output->section('Directory Structure Setup');

        $path = $this->getRootDirectoryPath();
        $path = $this->setupDefaultInstallDirectory($input, $output, $path);

        $output->writeln('Setup will now create the directory structure in your chosen location');

        $directories = $this->directoryStructure();
        $structure = [];
        foreach ($directories as $directory) {
            $this->ensureDirectoryExistsAndIsWritable($path, $directory, $output);
            $structure[] = $this->getRealPath($path, $directory);
        }

        $options = [
            FilesystemManagerInterface::KEYRING => $structure[3],
            FilesystemManagerInterface::CHECKSUM => $structure[3],
            FilesystemManagerInterface::ENVIRONMENT => $path,
            FilesystemManagerInterface::MASTER_KEYS => $structure[4],
            FilesystemManagerInterface::VAULT => $structure[5],
        ];

        $this->filesystemManager = $this->setup->get('filesystem_manager')->setup($options);
    }

    private function setupMasterKeyStorage(
        InputInterface $input,
        OutputInterface $output
    ): string {
        $loaders = $this->getKeyLoaders();
        if (empty($loaders)) {
            throw new \Exception(sprintf('At least one adapter should implement %s', KeyStorageInterface::class));
        }

        $helper = $this->getHelper('question');
        if (!$input->getOption('key-storage')) {
            if (count($loaders) === 1) {
                $input->setOption('key-storage', $loaders[0]);
            } else {
                $question = new ChoiceQuestion('Choose how you want to store your master encryption keys:', $loaders, 'env');
                $question->setErrorMessage('Choice %s is invalid.');
                $loader = $helper->ask($input, $output, $question);
                $input->setOption('key-storage', $loader);
            }
        }

        return $input->getOption('key-storage');
    }


    private function generateEncryptionKey(
        OutputInterface $output,
        string $adapter,
        string $storage,
        bool $overwrite,
    ): void {
        $type = KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY;
        $name = MasterKeyProviderInterface::MASTER_SYMMETRIC_ENCRYPTION_KEY;

        $delegator = $this->setup->get('delegating_key_loader')->setup($this->keyLoaders);

        $loader = $delegator->getLoader($storage);
        $contents = $loader->import($name);
        if (is_null($contents)) {
            $contents = $name;
        }
        try {
            $key = $loader->resolve($contents);
        } catch (UnableToLoadKeyException $exception) {
            $key = null;
        }

        if (!is_null($key) && $overwrite === false) {
            $output->writeln('Master encryption key already present.');
            return;
        }

        $output->writeln('Generating master encryption key.');

        $factory = $this->setup->get('key_factory')->setup($this->factoryAdapters);

        $config = new KeyConfig($type);
        $key = $factory->generateKey($config, $adapter);

        $loader->save($name, $key);

        $output->writeln('Master encryption key generated successfully.');
    }

    private function generateSignatureKeyPair(
        OutputInterface $output,
        string $adapter,
        string $storage,
        bool $overwrite,
    ): void {
        $type = KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR;
        $secretType = KeyFactoryInterface::ASYMMETRIC_SIGNATURE_SECRET_KEY;
        $publicType = KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY;
        $name = MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_KEY_PAIR;
        $secretName = MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_SECRET_KEY;
        $publicName = MasterKeyProviderInterface::MASTER_ASYMMETRIC_SIGNATURE_PUBLIC_KEY;

        $delegator = $this->setup->get('delegating_key_loader')->setup($this->keyLoaders);

        $loader = $delegator->getLoader($storage);
        $contents = $loader->import($secretName);
        if (is_null($contents)) {
            $contents = $secretName;
        }
        try {
            $key = $loader->resolve($contents);
        } catch (UnableToLoadKeyException $exception) {
            $key = null;
        }

        if (!is_null($key) && $overwrite === false) {
            $output->writeln('Signature key pair already present.');
            return;
        }

        $output->writeln('Generating signature key pair.');

        $factory = $this->setup->get('key_factory')->setup($this->factoryAdapters);

        $config = new KeyConfig($type);
        $keypair = $factory->generateKey($config, $adapter);
        $adapter = $factory->getAdapter($adapter);
        $keyType = $adapter->getAdapterSpecificKeyType($keypair);
        $keypair = $adapter->splitKeyPair($keypair, $keyType);

        foreach ($keypair as $key) {
            if ($key->getType() === $secretType) {
                $loader->save($secretName, $key);
            }
            if ($key->getType() === $publicType) {
                $loader->save($publicName, $key);
            }
        }

        $output->writeln('Signature key pair generated successfully.');
    }

    private function generateMasterKeys(
        OutputInterface $output,
        string $adapter,
        string $storage,
        bool $overwrite,
    ): void {
        $this->generateEncryptionKey($output, $adapter, $storage, $overwrite);
        $this->generateSignatureKeyPair($output, $adapter, $storage, $overwrite);
    }

    private function generateKeyring(
        OutputInterface $output,
        string $environment,
        string $encryption,
        string $storage,
        bool $overwrite,
    ): void {
        $name = $environment;
        if ($overwrite === false) {
            $name = $name . '_' . Utility::createUniqueId(6);
        }

        $adapter = $this->getEncryptionAdapter($encryption);

        $manager = $this->setup->get('key_manager')->setup(
            $this->filesystemManager,
            $adapter,
            $this->factoryAdapters,
            $this->keyLoaders,
            $storage,
            $name
        );

        $output->writeln(\sprintf('Creating keyring "%s".', $name));

        $auth = $manager->newKeyring();
        $manager->saveKeyring($auth);

        $keyName = \sprintf('%s_keyring_auth', $name);

        $output->writeln(\sprintf('Saving auth key "%s" in your key storage.', $keyName));

        $delegator = $this->setup->get('delegating_key_loader')->setup($this->keyLoaders);

        $loader = $delegator->getLoader($storage);
        $loader->save($keyName, $auth);

        $output->writeln('Keyring was created successfully.');
    }

    // TODO: Unfinished.
    private function createConfigurationFile(
        InputInterface $input,
        OutputInterface $output
    ): void {
        $install = $input->getOption('install-directory');

        $directories = $this->directoryStructure();
        $path = $this->getRealPath($install, $directories[2]);

        $filesystem = $this->setup->get('filesystem_adapter')->setup($path);

        $config = [
            'key_manager' => [
                'get_file_system_manager',
                'get_master_key_provider',
                'get_halite_encryption_adapter',
                'get_key_factory',
                'test'
            ],
            'file_system_manager' => [
            ]
        ];
    }
}
