<?php

namespace Nmap;

use SimpleXMLElement;
use Symfony\Component\Filesystem\Exception\FileNotFoundException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Exception\RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

class XmlOutputParser
{
    /**
     * Default path on Linux, perhaps in future add Windows support.
     */
    public static string $defaultDtd = '/usr/share/nmap/nmap.dtd';

    public static string $xmlCloseTag = '</nmaprun>';

    protected Filesystem $filesystem;

    protected string $xmlFile;

    public function __construct(string $xmlFile)
    {
        $filesystem = new Filesystem();
        if (!$filesystem->exists($xmlFile)) {
            throw new FileNotFoundException($xmlFile);
        }
        $this->filesystem = $filesystem;
        $this->xmlFile = $xmlFile;
    }

    public function getXmlFile(): string
    {
        return $this->xmlFile;
    }

    /**
     * Check if DTD is present under default install path. If not attempt to download
     * the most recent.
     *
     * todo: refresh latast dtd and change path to __DIR__ . '/../tmp/nmap.dtd';
     *
     * @link https://nmap.org/book/app-nmap-dtd.html
     */
    private function getDtdFiles(?string $dtdPath = ''): array
    {
        $dtds = [];

        if (!is_string($dtdPath) || empty($dtdPath)) {
            $dtdPath = self::$defaultDtd;
        }

        if ($this->filesystem->exists($dtdPath)) {
            $dtds[] = $dtdPath;
        }

        // Download latest official Nmap DTD
        $dtdPath = '/tmp/nmap.dtd';
        if (!$this->filesystem->exists($dtdPath)) {
            $str = file_get_contents('https://svn.nmap.org/nmap/docs/nmap.dtd');

            if (!is_string($str)) {
                throw new \InvalidArgumentException("Could not download https://svn.nmap.org/nmap/docs/nmap.dtd?");
            }
            $this->filesystem->dumpFile($dtdPath, $str);
        }
        $dtds[] = $dtdPath;

        return $dtds;
    }

    /**
     * DTD Validation is done using xmlstarlet because this is very cumbersome using standard PHP.
     * Besides validation, xmlstarlet contains other useful features for future development.
     *
     * @link http://xmlstar.sourceforge.net/
     */
    private function getXmlstarlet(): string
    {
        $xmlstarlet = (new ExecutableFinder)->find('xmlstarlet');

        if (!is_string($xmlstarlet) || empty($xmlstarlet)) {
            throw new RuntimeException('xmlstarlet could not be found');
        }
        return $xmlstarlet;
    }

    /**
     * Validate output file using DTD as recommended by Nmap.
     *
     * Validation can fail if a much newer or older DTD is used than the Nmap version that created
     * the output. Start validation with installed version, if fails or missing fetch latest DTD.
     *
     * @return bool|string true if valid, an error string if invalid
     * @link http://xmlstar.sourceforge.net/doc/UG/ch04s04.html
     * @todo: optimize this to find DTD that is associated with nmap version.
     */
    public function validate(?string $dtdPath = null): bool|string
    {
        $dtdFiles = $this->getDtdFiles($dtdPath);
        $len = count($dtdFiles);
        foreach ($dtdFiles as $index => $dtdFile) {
            $process = new Process([
                $this->getXmlstarlet(),
                'val',
                '-e',
                '--dtd', $dtdFile,
                $this->xmlFile
            ]);
            $process->setTimeout(900);
            $process->run();

            $error = $process->getErrorOutput();
            if (empty($error)) {
                return true;
            }
            if ($index == $len - 1) {
                return $error;
            }
        }
        return 'Error';
    }

    /**
     * Nmap scans that have been cancelled/failed miss the XML closing element.
     *
     * This method is currently a simple attempt to 'fix' the XML by appending the XML closing tag. A copy of
     * the original file is used, a new file is written to the directory 'recovered'. The xmlFile to import
     * will be set to the recovered file. Note: This does not result in a XML that passes DTD validation.
     * However, the input can be be parsed.
     *
     * todo: perhaps 'xmlstarlet do --recover' could be used for recovery (also more for more complex cases).
     *   However, 'xmlstartlet' appears to adjust the encoding, it is unclear what the impact of this is.
     */
    public function attemptFixInvalidFile(): bool
    {
        $str = file_get_contents($this->xmlFile);

        if (!is_string($str)) {
            throw new \InvalidArgumentException("Could not get contents of file: {$this->xmlFile}");
        }


        if (preg_match('%' . preg_quote(XmlOutputParser::$xmlCloseTag) . '\s+$%m', $str)) {
            return false;
        }

        $pathinfo = pathinfo($this->xmlFile);
        $recoveryDir = $pathinfo['dirname'] . '/recovered';
        if (!$this->filesystem->exists($recoveryDir)) {
            $this->filesystem->mkdir($recoveryDir);
        }

        $newXmlPath = $recoveryDir . '/' . $pathinfo['basename'];
        $this->filesystem->copy($this->xmlFile, $newXmlPath);
        $this->filesystem->appendToFile($newXmlPath, XmlOutputParser::$xmlCloseTag);
        $this->xmlFile = $newXmlPath;
        return true;
    }

    /**
     * @return Host[]
     */
    public function parse(): array
    {
        $xml = simplexml_load_file($this->xmlFile);

        if (!$xml instanceof SimpleXMLElement || !isset($xml->runstats->hosts)) {
            throw new \InvalidArgumentException("{$this->xmlFile} does not appear to be valid.");
        }

        if ((string)$xml->runstats->hosts->attributes()->up === '0') {
            return [];
        }

        if (!isset($xml->host)) {
            throw new \InvalidArgumentException("{$this->xmlFile} does not appear to be valid.");
        }

        $hosts = [];
        foreach ($xml->host as $xmlHost) {
            if (!$xmlHost instanceof SimpleXMLElement) {
                continue; // shouldn't be possible?
            }

            $state = $xmlHost->status?->attributes()?->state ?? null;
            if ($state === null) {
                // ? log ? throw?
                continue;
            }

            $ports = $xmlHost->ports;

            if (!$ports instanceof SimpleXMLElement) {
                continue; // ? log ? throw?
            }

            if (isset($ports->port)) {
                $port = self::parsePorts($ports->port);
            } else {
                $port = [];
            }

            // <hostnames></hostnames> is possible.
            $host = new Host(
                self::parseAddresses($xmlHost),
                (string)$state,
                (isset($xmlHost->hostnames) && isset($xmlHost->hostnames->hostname)) ?
                    self::parseHostnames($xmlHost->hostnames->hostname) : [],
                $port
            );

            $script = $xmlHost->hostscript->script ?? null;

            if ($script !== null) {
                $host->setScripts(self::parseScripts($script));
            }
            if (isset($xmlHost->os->osmatch)) {
                $osName = $xmlHost->os->osmatch->attributes()->name ?? null;
                $osAccuracy = $xmlHost->os->osmatch->attributes()->accuracy ?? null;

                if ($osName !== null) {
                    $host->setOs((string)$osName);
                }

                if ($osAccuracy !== null) {
                    $host->setOsAccuracy((int)$osAccuracy);
                }
            }
            $hosts[] = $host;
        }

        return $hosts;
    }

    /**
     * @return Hostname[]
     */
    public static function parseHostnames(SimpleXMLElement $xmlHostnames): array
    {
        $hostnames = [];
        foreach ($xmlHostnames as $hostname) {
            $attrs = $hostname->attributes();
            $name = $type = null;
            if (!is_null($attrs)) {
                $name = $attrs->name;
                $type = $attrs->type;
            }

            if (!is_null($name) && !is_null($type)) {
                $hostnames[] = new Hostname((string)$name, (string)$type);
            }
        }

        return $hostnames;
    }

    /**
     * @return Script[]
     */
    public static function parseScripts(SimpleXMLElement $xmlScripts): array
    {
        $scripts = [];
        foreach ($xmlScripts as $xmlScript) {
            $attrs = $xmlScript->attributes();
            if (null === $attrs || $attrs->id === null || $attrs->output === null) {
                continue;
            }
            $scripts[] = new Script(
                (string)$attrs->id,
                (string)$attrs->output,
                isset($xmlScript->elem) || isset($xmlScript->table) ? self::parseScriptElems($xmlScript) : []
            );
        }

        return $scripts;
    }

    public static function parseScriptElem(SimpleXMLElement $xmlElems): array
    {
        $elems = [];
        foreach ($xmlElems as $xmlElem) {
            $attrs = $xmlElem->attributes();

            if ($attrs === null) {
                continue;
            }

            if (empty($attrs)) {
                $elems[] = (string)$xmlElem[0];
            } else {
                $key = $attrs->key ?? null;
                if ($key === null) {
                    continue;
                }
                $key = (string)$key;
                $elems[$key] = (string)$xmlElem[0];
            }
        }
        return $elems;
    }

    public static function parseScriptElems(SimpleXMLElement $xmlScript): array
    {
        if (isset($xmlScript->table)) {
            $elems = [];
            foreach ($xmlScript->table as $xmlTable) {
                $attributes = $xmlTable->attributes();
                if ($attributes === null) {
                    continue;
                }

                $key = $attributes->key;
                if ($key === null) {
                    continue;
                }
                $key = (string)$key;

                $elem = $xmlTable->elem ?? null;

                if (!is_null($elem)) {
                    $elems[$key] = self::parseScriptElem($elem);
                }
            }
            return $elems;
        }

        $elem = $xmlScript->elem ?? null;
        if (!is_null($elem)) {
            return self::parseScriptElem($elem);
        }
        throw new \InvalidArgumentException("XML must contain either a table for a single elem element");
    }

    /**
     * @return Port[]
     */
    public static function parsePorts(SimpleXMLElement $xmlPorts): array
    {
        $ports = [];
        foreach ($xmlPorts as $xmlPort) {
            $name = $product = $version = null;

            if ($xmlPort->service !== null) {
                $attrs = $xmlPort->service->attributes();
                if (!is_null($attrs)) {
                    $name = (string)$attrs->name;
                    $product = (string)$attrs->product;
                    $version = (string)$attrs->version;
                }
            }

            $service = new Service(
                $name,
                $product,
                $version
            );

            $attrs = $xmlPort->attributes();
            if (!is_null($attrs) && !is_null($xmlPort->state)) {
                $state = $xmlPort->state->attributes()->state ?? null;

                if ($state === null) {
                    // ?? throw ? log ?
                    continue;
                }

                $port = new Port(
                    (int)$attrs->portid,
                    (string)$attrs->protocol,
                    (string)$state,
                    $service
                );
                if (isset($xmlPort->script)) {
                    $port->setScripts(self::parseScripts($xmlPort->script));
                }
                $ports[] = $port;
            }
        }

        return $ports;
    }

    /**
     * @return Address[]
     */
    public static function parseAddresses(SimpleXMLElement $host): array
    {
        $addresses = [];

        $iter = $host->xpath('./address');

        if ($iter === false || $iter === null) {
            return $addresses;
        }
        foreach ($iter as $address) {
            $attributes = $address->attributes();
            if (is_null($attributes)) {
                continue;
            }
            $addresses[(string)$attributes->addr] = new Address(
                (string)$attributes->addr,
                (string)$attributes->addrtype,
                isset($attributes->vendor) ? (string)$attributes->vendor : ''
            );
        }

        return $addresses;
    }
}
