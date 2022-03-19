<?php

/**
 * This file is part of the nmap package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */

namespace Nmap;

/**
 * @author William Durand <william.durand1@gmail.com>
 */
class Port
{
    const STATE_OPEN   = 'open';

    const STATE_CLOSED = 'closed';

    private $number;

    private $protocol;

    private $state;

    private $service;

    private $scripts = [];

    public function __construct(int $number, string $protocol, string $state, Service $service)
    {
        $this->number   = (int) $number;
        $this->protocol = $protocol;
        $this->state    = $state;
        $this->service  = $service;
    }

    public function setScripts(array $scripts)
    {
        $this->scripts = $scripts;
    }

    /**
     * @return integer
     */
    public function getNumber()
    {
        return $this->number;
    }

    /**
     * @return string
     */
    public function getProtocol()
    {
        return $this->protocol;
    }

    /**
     * @return string one of self::STATE_OPEN or STATE_CLOSED
     */
    public function getState()
    {
        return $this->state;
    }


    public function isOpen() : bool
    {
        return self::STATE_OPEN === $this->state;
    }

    public function isClosed() : bool
    {
        return self::STATE_CLOSED === $this->state;
    }

    /**
     * @return Service
     */
    public function getService() : Service
    {
        return $this->service;
    }

    /**
     * @return Script[]
     */
    public function getScripts() : array
    {
        return $this->scripts;
    }
}
