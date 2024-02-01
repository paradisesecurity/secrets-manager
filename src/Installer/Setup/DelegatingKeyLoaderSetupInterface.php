<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Installer\Setup;

use Doctrine\Common\Collections\Collection;
use ParadiseSecurity\Component\SecretsManager\Loader\DelegatingKeyLoaderInterface;

interface DelegatingKeyLoaderSetupInterface extends SetupInterface
{
    public function setup(Collection $loaders): DelegatingKeyLoaderInterface;
}
