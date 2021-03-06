import unittest
from ctypes import *
from nose.tools import ok_, eq_, raises
from capper._libpcap import PcapPkthd
from capper._wrapper import (
    Pcap,
    PcapException,
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

    def test_open_dead(self):
        dev =self.pcap.dead(1, 1024)
        ok_(dev)

    def test_get_nonblock(self):
        dev = self.pcap.create(self.pcap.device)
        ok_(-1 != self.pcap.get_nonblock(dev) )

    def test_set_nonblock(self):
        dev = self.pcap.create(self.pcap.device)
        ok_(-1 != self.pcap.set_nonblock(dev, 0) )

    def test_inject(self):
        dev = self.pcap.create(self.pcap.device)
        str_bytes = '0123456789'
        eq_(
            0,
            self.pcap.inject(
                dev,
                str_bytes,
            )
        )

    def test_sendpacket(self):
        dev = self.pcap.create(self.pcap.device)
        str_bytes = '0123456789'
        eq_(
            0,
            self.pcap.sendpacket(
                dev,
                str_bytes,
            )
        )

    def test_stamp_types(self):
        return
        dev = self.pcap.create(self.pcap.device)
        ok_(self.pcap.stamp_types(dev))

    def test_stamp_name(self):
        return
        dev = self.pcap.create(self.pcap.device)
        stamps = self.pcap.stamp_types(dev)
        stamp  = stamps.object.value
        ok_(self.pcap.stamp_name(stamp))

    def test_stamp_desc(self):
        return
        dev = self.pcap.create(self.pcap.device)
        stamps = self.pcap.stamp_types(dev)
        stamp  = stamps.object.value
        ok_(self.pcap.stamp_desc(stamp))

    def test_datalink(self):
        dev = self.pcap.create(self.pcap.device)
        act_dev = self.pcap.activate(dev)
        ok_(self.pcap.datalink(dev))

    def test_can_set_rfmon(self):
        dev = self.pcap.create(self.pcap.device)
        ok_(self.pcap.can_set_rfmon(dev))

    def test_loop(self):
        # create the device
        dev = self.pcap.create(self.pcap.device)
        # setup callback
        def cb(args, pkthdr, pkt):
            print args, pkthdr, pkt
            return None

        CBFUN = CFUNCTYPE(c_char_p, PcapPkthd, c_char_p)
        cb_fun = CBFUN(cb)
        #l  = self.pcap.loop(dev, 1, PcapPkthd(), None)
        l  = self.pcap.loop(dev, 1, cb_fun, None)
        ok_(l >= 0)

    def test_next_packet(self):
        dev = self.pcap.create(self.pcap.device)
        ret, pkt = self.pcap.next_packet(dev)
        ok_(pkt)

    def test_set_snaplen(self):
        dev      = self.pcap.create(self.pcap.device)
        snap_set = self.pcap.set_snaplen(dev, 10)
        eq_(0, snap_set)
        # try setting it on active, raises error
        self.pcap.activate(dev)
        self.assertRaises(
            PcapException,
            self.pcap.set_snaplen,
            dev,
            10
        )

    def test_get_snaplen(self):
        dev      = self.pcap.create(self.pcap.device)
        snap_set = self.pcap.set_snaplen(dev, 10)
        self.pcap.activate(dev)
        snap_get = self.pcap.get_snaplen(dev)
        eq_(snap_len, snap_get)

    def test_set_timeout(self):
        dev      = self.pcap.create(self.pcap.device)
        to_set   = self.pcap.set_timeout(dev, 100)
        eq_(0, to_set)
        self.pcap.activate(dev)
        self.assertRaises(
            PcapException,
            self.pcap.set_timeout,
            dev,
            10
        )

    def test_is_swapped(self):
        dev = self.pcap.create(self.pcap.device)
        ok_(self.pcap.is_swapped(dev))

    def tearDown(self):
        pass
