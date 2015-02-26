import unittest
from nose.tools import ok_, eq_, raises
from capper._wrapper import (
    Pcap,
    PcapExecption,
)


class TestPcap(unittest.TestCase):

    def setUp(self):
        self.pcap = Pcap()

    def test_device(self):
        ok_(bool(self.pcap.device))

    def test_version(self):
        ok_(bool(self.pcap.version))

    def test_create(self):
        ok_(self.pcap.create('test'))

    @raises(PcapExecption)
    def test_open_uninitialized(self):
        ok_(self.pcap.open(
            'foo',
            1,
            True,
            100
        ))

    @raises(PcapExecption)
    def test_lookup_net_unconfigured(self):
        ok_(self.pcap.lookup_net(
            'foo',
            1,
            1
        ))

    def test_devices(self):
        ok_(self.pcap.devices)

    def tearDown(self):
        pass

