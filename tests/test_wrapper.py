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

    def test_inject(self):
        dev = self.pcap.create(self.pcap.device)
        eq_(
            0,
            self.pcap.inject(
                dev,
                b'bytesofapacket',
            )
        )

    def test_sendpacket(self):
        dev = self.pcap.create(self.pcap.device)
        eq_(
            0,
            self.pcap.sendpacket(
                dev,
                b'bytesofapacket',
            )
        )

    def test_stamp_types(self):
        dev = self.pcap.create(self.pcap.device)
        ok_(self.pcap.stamp_types(dev))

    def test_stamp_name(self):
        dev = self.pcap.create(self.pcap.device)
        stamps = self.pcap.stamp_types(dev)
        stamp  = stamps.object.value
        ok_(self.pcap.stamp_name(stamp))

    def test_stamp_desc(self):
        dev = self.pcap.create(self.pcap.device)
        stamps = self.pcap.stamp_types(dev)
        stamp  = stamps.object.value
        ok_(self.pcap.stamp_desc(stamp))

    def tearDown(self):
        pass

