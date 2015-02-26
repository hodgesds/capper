from   ctypes import *
import abc
import platform
import os
import sys
import struct
arch = 8 * struct.calcsize("P")

pf = platform.platform()

c_int_p    = POINTER(c_int)
c_uint_p   = POINTER(c_uint)
c_short_p  = POINTER(c_short)
c_ushort_p = POINTER(c_ushort)


def load_libpcap():
    pcap = 'libpcap.so'
    if 'darwin' in pf.lower():
        pcap = 'libpcap.1.8.0-PRE-GIT.dylib'
    return CDLL(pcap)


class PCAP(Structure):
    pass

class PcapFileHeader(Structure):
    _fields_ = [
        ('magic', c_uint),
        ('version_major', c_ushort),
        ('version_minor', c_ushort),
        ('thiszone',      c_int),
        ('sigfigs',       c_uint),
        ('snaplen',       c_uint),
        ('linktype',      c_uint),
    ]

class TimeVal(Structure):
    _fields_ = [
        ('tv_sec', c_uint),
        ('tv_usec', c_uint),
    ]

class PcapPkthd(Structure):
    _fields_ = [
        ('ts',     POINTER(TimeVal)),
        ('caplen', c_uint),
        ('len',    c_uint),
    ]


class PcapStat(Structure):
    _fields_ = [
        ('ps_recv',   c_uint),
        ('ps_drop',   c_uint),
        ('ps_ifdrop', c_uint),
    ]
    if 'win' in pf:
        _fields_.append(('bs_capt', c_uint))


class PcapStatEx(Structure):
    _fields_ = [
        ('rx_packets',          c_ulong),
        ('tx_packets',          c_ulong),
        ('rx_bytes',            c_ulong),
        ('tx_bytes',            c_ulong),
        ('rx_errors',           c_ulong),
        ('tx_errors',           c_ulong),
        ('rx_dropped',          c_ulong),
        ('tx_dropped',          c_ulong),
        ('multicast',           c_ulong),
        ('collisions',          c_ulong),
        ('rx_length_errors',    c_ulong),
        ('rx_over_errors',      c_ulong),
        ('rx_crc_errors',       c_ulong),
        ('rx_frame_errors',     c_ulong),
        ('rx_fifo_errors',      c_ulong),
        ('rx_missed_errors',    c_ulong),
        ('tx_aborted_errors',   c_ulong),
        ('tx_carrier_errors',   c_ulong),
        ('tx_fifo_errors',      c_ulong),
        ('tx_heartbeat_errors', c_ulong),
        ('tx_window_errors',    c_ulong),
    ]
    def __init__(self, *args, **kwargs):
        if 'win' not in pf.lower():
            raise Exception('Windows only')


class PcapIf(Structure):
    pass

class Addresses(Structure):
    pass

PcapIf._fields_ = [
    ('next',     POINTER(PcapIf)),
    ('name',     c_char),
    ('pcap_add', POINTER(Addresses)),
    ('flags',    c_uint),
]


class BaseHandler:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def handle(self):
        pass

def c_handle(func):
    HANDLE_FUN = CFUNCTYPE(c_char_p, POINTER(PcapPkthd), c_char_p)
    return HANDLE_FUN(func)

class GenericHandler(BaseHandler):

    def _handle(self):
        args    = args_p.value
        pkt_hdr = pkt_hdr_p.value
        pkt     = pkt_p.value
        print args, pkt_hdr, pkt

    @c_handle
    def handle(self, args_p, pkt_hdr_p, pkt_p):
        args    = args_p.value
        pkt_hdr = pkt_hdr_p.value
        pkt     = pkt_p.value
        print args, pkt_hdr, pkt


#class PcapAddr(Structure):
    #pass

#PcapAddr._fields_ = [
    #('next',      POINTER(PcapAddr)),
    #('addr',      POINTER(sockaddr)),
    #('netmask',   POINTER(sockaddr)),
    #('broadaddr', POINTER(sockaddr)),
    #('dstaddr',   POINTER(sockaddr)),
#]


