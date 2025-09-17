<?php

namespace Nmap\Tests;

use Mockery as m;
use Nmap\Address;
use Nmap\Host;
use Nmap\Nmap;
use Nmap\Port;
use Nmap\XmlOutputParser;

class NmapTest extends TestCase
{

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();

        if ($this->filesystem->exists($recoverDir = __DIR__ . '/Fixtures/Validation/recovered')) {
            $this->filesystem->remove($recoverDir);
        }
    }

    public function testScanBasic()
    {
        $outputFile = __DIR__ . '/Fixtures/test_scan.xml';

        $expectedCommand = ["nmap", "-oX", $outputFile, '--', 'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);


        $nmap = new Nmap($executor, $outputFile);
        $hosts = $nmap->scan(['williamdurand.fr']);
        $this->assertCount(1, $hosts);

        $host = current($hosts);

        $this->assertCount(2, $host->getAddresses());
        $this->assertEquals('204.232.175.78', current($host->getIpv4Addresses())->getAddress());
        $this->assertArrayHasKey('204.232.175.78', $host->getIpv4Addresses());
        $this->assertArrayNotHasKey('00:C0:49:00:11:22', $host->getIpv4Addresses());
        $this->assertEquals(Address::TYPE_IPV4, current($host->getIpv4Addresses())->getType());
        $this->assertEmpty(current($host->getIpv4Addresses())->getVendor());
        $this->assertEquals('00:C0:49:00:11:22', current($host->getMacAddresses())->getAddress());
        $this->assertArrayHasKey('00:C0:49:00:11:22', $host->getMacAddresses());
        $this->assertArrayNotHasKey('204.232.175.78', $host->getMacAddresses());
        $this->assertEquals(Address::TYPE_MAC, current($host->getMacAddresses())->getType());
        $this->assertEquals('U.S. Robotics', current($host->getMacAddresses())->getVendor());
        $this->assertEquals(Host::STATE_UP, $host->getState());

        $hostnames = $host->getHostnames();
        $this->assertCount(2, $hostnames);
        $this->assertEquals('williamdurand.fr', $hostnames[0]->getName());
        $this->assertEquals('user', $hostnames[0]->getType());
        $this->assertEquals('pages.github.com', $hostnames[1]->getName());
        $this->assertEquals('PTR', $hostnames[1]->getType());

        $ports = $host->getPorts();
        $this->assertCount(5, $ports);
        $this->assertCount(3, $host->getOpenPorts());
        $this->assertCount(2, $host->getClosedPorts());

        $this->assertEquals(22, $ports[0]->getNumber());
        $this->assertEquals('tcp', $ports[0]->getProtocol());
        $this->assertEquals(Port::STATE_OPEN, $ports[0]->getState());
        $this->assertNotNull($ports[0]->getService());
        $this->assertEquals('ssh', $ports[0]->getService()->getName());
    }

    public function testScanSpecifyingPorts()
    {
        $outputFile = __DIR__ . '/Fixtures/test_scan_specifying_ports.xml';

        $expectedCommand = ["nmap", "-p 21,22,80", "-oX", $outputFile, '--', 'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);

        $nmap = new Nmap($executor, $outputFile);
        $hosts = $nmap->scan(['williamdurand.fr'], [21, 22, 80]);
        $this->assertCount(1, $hosts);

        $host = current($hosts);

        $this->assertCount(1, $host->getAddresses());
        $this->assertEquals('204.232.175.78', current($host->getIpv4Addresses())->getAddress());
        $this->assertArrayHasKey('204.232.175.78', $host->getIpv4Addresses());
        $this->assertEquals(Address::TYPE_IPV4, current($host->getIpv4Addresses())->getType());
        $this->assertEmpty(current($host->getIpv4Addresses())->getVendor());
        $this->assertEquals(Host::STATE_UP, $host->getState());

        $hostnames = $host->getHostnames();
        $this->assertCount(2, $hostnames);
        $this->assertEquals('williamdurand.fr', $hostnames[0]->getName());
        $this->assertEquals('user', $hostnames[0]->getType());
        $this->assertEquals('pages.github.com', $hostnames[1]->getName());
        $this->assertEquals('PTR', $hostnames[1]->getType());

        $ports = $host->getPorts();
        $this->assertCount(3, $ports);

        $this->assertEquals(21, $ports[0]->getNumber());
        $this->assertEquals('ftp', $ports[0]->getService()->getName());
        $this->assertEquals(22, $ports[1]->getNumber());
        $this->assertEquals('ssh', $ports[1]->getService()->getName());
        $this->assertEquals(80, $ports[2]->getNumber());
        $this->assertEquals('http', $ports[2]->getService()->getName());
    }

    public function testScanWithOsDetection()
    {
        $outputFile = __DIR__ . '/Fixtures/test_scan_with_os_detection.xml';
        $expectedCommand = ["nmap", "-O", "-oX", $outputFile, '--', 'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);

        $nmap = new Nmap($executor, $outputFile);
        $hosts = $nmap
            ->enableOsDetection()
            ->scan(['williamdurand.fr']);

        $this->assertEquals($hosts[0]->getOs(), 'Cisco SRP 521W WAP (Linux 2.6)');
        $this->assertEquals($hosts[0]->getOsAccuracy(), 93);
    }

    public function testScanWithServiceInfo()
    {
        $outputFile = __DIR__ . '/Fixtures/test_scan_with_service_info.xml';
        $expectedCommand = ["nmap", "-sV", "-oX", $outputFile, '--',  'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);

        $nmap = new Nmap($executor, $outputFile);
        $hosts = $nmap
            ->enableServiceInfo()
            ->scan(['williamdurand.fr']);

        $host = current($hosts);
        $ports = $host->getPorts();

        $service = $ports[0]->getService();
        $this->assertEquals('ssh', $service->getName());
        $this->assertEquals('OpenSSH', $service->getProduct());
        $this->assertEquals('5.1p1 Debian 5github8', $service->getVersion());

        $service = $ports[1]->getService();
        $this->assertEquals('http', $service->getName());
        $this->assertEquals('nginx', $service->getProduct());
    }

    public function testScanWithVerbose()
    {
        $outputFile = __DIR__ . '/Fixtures/test_scan_with_verbose.xml';
        $expectedCommand = ["nmap", "-v", "-oX", $outputFile, '--', 'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);

        $nmap = new Nmap($executor, $outputFile);

        $hosts = $nmap
            ->enableVerbose()
            ->scan(['williamdurand.fr']);

        $this->assertNotEmpty($hosts);
    }

    public function testPingScan()
    {
        $outputFile = __DIR__ . '/Fixtures/test_ping_scan.xml';
        $expectedCommand = ["nmap", "-sn", "-oX", $outputFile, '--', 'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);

        $nmap = new Nmap($executor, $outputFile);
        $hosts = $nmap
            ->disablePortScan()
            ->scan(['williamdurand.fr']);

        $this->assertNotEmpty($hosts);
    }

    public function testScanWithoutReverseDNS()
    {
        $outputFile = __DIR__ . '/Fixtures/test_ping_without_reverse_dns.xml';
        $expectedCommand = ["nmap", "-n", "-oX", $outputFile, '--', 'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);

        $nmap = new Nmap($executor, $outputFile);
        $hosts = $nmap
            ->disableReverseDNS()
            ->scan(['williamdurand.fr']);

        $this->assertNotEmpty($hosts);
    }

    public function testScanWithTreatHostsAsOnline()
    {
        $outputFile = __DIR__ . '/Fixtures/test_scan_with_verbose.xml';
        $expectedCommand = ["nmap", "-Pn", "-oX", $outputFile, '--', 'williamdurand.fr'];

        $executor = $this->getProcessExecutorMock($expectedCommand);

        $nmap = new Nmap($executor, $outputFile);
        $hosts = $nmap->treatHostsAsOnline()->scan(['williamdurand.fr']);

        $this->assertNotEmpty($nmap);
    }

    public function testScanWithUserTimeout()
    {
        $outputFile = __DIR__ . '/Fixtures/test_scan.xml';
        $timeout = 123;

        $mock = m::mock(\Nmap\Util\ProcessExecutor::class);

        $mock->shouldReceive('execute')->withArgs(
            function (array $args) {
                return $args[1] == ' -h';
            })->once()->andReturn(0);

        $mock->shouldReceive('execute')->withArgs(
            function ($args, $timeout) {
                return $timeout == 123;
            })->once()->andReturn(0);

        $nmap = new Nmap($mock, $outputFile);
        $nmap->setTimeout($timeout)->scan(['williamdurand.fr']);
    }

    public function testExecutableNotExecutable()
    {
        $mock = m::mock(\Nmap\Util\ProcessExecutor::class);

        $mock->shouldReceive('execute')->withArgs(
            function (array $args) {
                return $args[1] == ' -h';
            })->once()->andReturn(1);


        $this->expectException(\InvalidArgumentException::class);
        new Nmap($mock);
    }

    /**
     * @return m\Mock
     */
    private function getProcessExecutorMock(array $expectedCommand)
    {
        $mock = m::mock(\Nmap\Util\ProcessExecutor::class);

        $mock->shouldReceive('execute')->withArgs(
            function (array $args) {
                return $args[1] == ' -h';
            })->once()->andReturn(0);

        $mock
            ->shouldReceive('execute')
            ->withArgs([
                $expectedCommand,
                60,
            ])
            ->once()
            ->andReturn(0);

        return $mock;
    }

    public function testExistingXmlOutputFileCanBeParsed()
    {
        $hosts = Nmap::parseOutput(__DIR__ . '/Fixtures/test_scan.xml');
        $host = current($hosts);
        $this->assertCount(1, $hosts);
        $this->assertCount(5, $host->getPorts());
    }

    public function testOutputValidationInvalid()
    {
        $parser = new XmlOutputParser(__DIR__ . '/Fixtures/Validation/test_interrupted_invalid.xml');
        $dtd = __DIR__ . '/Fixtures/Validation/nmap.dtd';
        $this->assertStringContainsString('Premature end of data in tag nmaprun', $parser->validate($dtd));
    }

    public function testOutputValidationValid()
    {
        $parser = new XmlOutputParser(__DIR__ . '/Fixtures/Validation/test_completed_valid.xml');
        $dtd = __DIR__ . '/Fixtures/Validation/nmap.dtd';
        $this->assertTrue($parser->validate($dtd));
    }

    public function testOutputDefaultDtdPath()
    {
        $this->assertFileExists(XmlOutputParser::$defaultDtd);
    }

    public function testOutputValidationValidByUsingDtdFallback()
    {
        $parser = new XmlOutputParser(__DIR__ . '/Fixtures/Validation/test_completed_valid.xml');
        $this->assertTrue($parser->validate('notavalidpath'));
    }

    public function testOutputFileRecovery()
    {
        // Invalid input
        $input = __DIR__ . '/Fixtures/Validation/test_interrupted_invalid.xml';
        $parser = new XmlOutputParser($input);
        $this->assertTrue($parser->attemptFixInvalidFile());

        // Assert recovery
        $output = __DIR__ . '/Fixtures/Validation/recovered/test_interrupted_invalid.xml';
        $this->assertFileExists($output);
        $this->assertTrue(filesize($output) > filesize($input));
        $this->assertStringEndsWith(XmlOutputParser::$xmlCloseTag, file_get_contents($output));
    }

    public function testOutputFileRecoveryOnValidFile()
    {
        $parser = new XmlOutputParser(__DIR__ . '/Fixtures/Validation/test_completed_valid.xml');
        $this->assertFalse($parser->attemptFixInvalidFile());
    }

    public function testBuildCommand()
    {

        $x = (new Nmap(null, '/tmp/test'))->buildCommand([], []);
        $this->assertEquals(['nmap', '-oX', '/tmp/test', '--'], $x);

        $x = (new Nmap(null, '/tmp/test'))->buildCommand(['facebook.com'], []);
        $this->assertEquals(['nmap', '-oX', '/tmp/test', '--', 'facebook.com'], $x);

        $x = (new Nmap(null, '/tmp/test'))->buildCommand(['facebook.com'], [80]);
        $this->assertEquals(['nmap', '-p 80', '-oX', '/tmp/test', '--', 'facebook.com'], $x);

        $x = (new Nmap(null, '/tmp/test'))->buildCommand(['facebook.com'], [80, 443]);
        $this->assertEquals(['nmap', '-p 80,443', '-oX', '/tmp/test', '--', 'facebook.com'], $x);


        $x = (new Nmap(null, '/tmp/test'))->buildCommand(['example.com', 'facebook.com'], [80, 443]);

        $this->assertEquals(['nmap', '-p 80,443', '-oX', '/tmp/test', '--', 'example.com', 'facebook.com'], $x);

        $x = (new Nmap(null, '/tmp/test'))
            ->disableReverseDNS(true)
            ->buildCommand(['example.com', 'facebook.com'], [80, 443]);
        $this->assertEquals(['nmap', '-p 80,443', '-n', '-oX', '/tmp/test', '--', 'example.com', 'facebook.com'], $x);
    }

}
