import os
import sys
import struct
import unittest
import platform
from   ctypes import *
from   nose.tools import ok_, eq_, raises
from   capper._libpcap import (
    load_libpcap,
    setup_libpcap,
)


class TestLibpcap(unittest.TestCase):
    def setUp(self):
        pass

    def test_load_libpcap(self):
        pcap = load_libpcap()
        ok_(pcap.pcap_lib_version(None))

    def tearDown(self):
        pass

