<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap;

class Service
{

    private ?string $name;

    private ?string $product;

    private ?string $version;

    public function __construct(?string $name = null, ?string $product = null, ?string $version = null)
    {
        $this->name = $name;
        $this->product = $product;
        $this->version = $version;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function getProduct(): ?string
    {
        return $this->product;
    }

    public function getVersion(): ?string
    {
        return $this->version;
    }
}
