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

    def test_devices(self):
        ok_(self.pcap.devices)

    def test_free_devices(self):
        self.pcap.devices
        self.pcap.free_devices()

    def test_get_nonblock(self):
        dev = self.pcap.create(self.pcap.device)
        ok_(-1 != self.pcap.get_nonblock(dev) )

    def test_set_nonblock(self):
        dev = self.pcap.create(self.pcap.device)
        ok_(-1 != self.pcap.set_nonblock(dev, 0) )

    def tearDown(self):
        pass

