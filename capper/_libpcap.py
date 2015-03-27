from   ctypes import *
import abc
import platform
import os
import sys
import struct

arch = 8 * struct.calcsize("P")
pf   = platform.platform()

c_int_p    = POINTER(c_int)
c_uint_p   = POINTER(c_uint)
c_short_p  = POINTER(c_short)
c_ushort_p = POINTER(c_ushort)


def load_libpcap():
    # XXX: refactor this for cross platform
    if 'LIBPCAP_LIB' in os.environ:
        return CDLL(os.environ.get('LIBPCAP_LIB'))

    pcap = 'libpcap.so'
    if 'darwin' in pf.lower():
        pcap = 'libpcap.1.8.0-PRE-GIT.dylib'
    return CDLL(pcap)


def setup_libpcap():
    libpcap = load_libpcap()

    libpcap.pcap_lookupdev.argtypes = [c_char_p]
    libpcap.pcap_lookupdev.restype  = c_char_p

    libpcap.pcap_list_tstamp_types.argtypes = [
        POINTER(PCAP),
        POINTER(c_int_p),
    ]
    libpcap.pcap_list_tstamp_types.restype  = c_int

    libpcap.pcap_lookupnet.argtypes = [
        c_char_p,
        POINTER(c_uint),
        POINTER(c_uint),
        c_char_p,
    ]
    libpcap.pcap_lookupnet.restype = c_int

    libpcap.pcap_statustostr.argtypes = [c_int]
    libpcap.pcap_statustostr.restype  = c_char

    libpcap.pcap_strerror.argtypes = [c_int]
    libpcap.pcap_strerror.restype  = c_char

    libpcap.pcap_geterr.argtypes = [POINTER(PCAP)]
    libpcap.pcap_geterr.restype  = c_char

    libpcap.pcap_next.argtypes = [POINTER(PCAP), POINTER(PcapPkthd)]
    libpcap.pcap_next.restype  = c_char

    libpcap.pcap_findalldevs.argtypes = [POINTER(POINTER(PcapIf)), c_char_p]
    libpcap.pcap_findalldevs.restype  = c_int

    libpcap.pcap_freealldevs.argtypes = [POINTER(PcapIf), c_char_p]
    libpcap.pcap_freealldevs.restype  = None

    # XXX:
    # libpcap.pcap_next_ex.argtypes = [c_int, POINTER(PcapPkthd)]
    # libpcap.pcap_next_ex.restype  = c_char

    libpcap.pcap_create.argtypes = [c_char_p, c_char_p]
    libpcap.pcap_create.restype  = POINTER(PCAP)

    libpcap.pcap_activate.argtypes = [POINTER(PCAP)]
    libpcap.pcap_activate.restype  = c_int

    libpcap.pcap_close.argtypes = [POINTER(PCAP)]
    libpcap.pcap_close.restype  = None

    libpcap.pcap_loop.argtypes = [
        POINTER(PCAP),
        c_int,
        HANDLE_FUN,
        c_char_p
    ]
    libpcap.pcap_loop.restype  = c_int

    libpcap.pcap_setnonblock.argtypes = [
        POINTER(PCAP),
        c_int,
        c_char_p
    ]
    libpcap.pcap_setnonblock.restype  = c_int

    libpcap.pcap_getnonblock.argtypes = [
        POINTER(PCAP),
        c_char_p
    ]
    libpcap.pcap_getnonblock.restype  = c_int

    libpcap.pcap_get_selectable_fd.argtypes = [POINTER(PCAP)]
    libpcap.pcap_get_selectable_fd.restype = c_int

    libpcap.pcap_breakloop.argtypes = [POINTER(PCAP)]
    libpcap.pcap_breakloop.restype  = None

    libpcap.pcap_inject.argtypes = [POINTER(PCAP), POINTER(c_void_p), c_int]
    libpcap.pcap_inject.restype  = c_int

    libpcap.pcap_sendpacket.argtypes = [POINTER(PCAP), POINTER(c_char_p), c_int]
    libpcap.pcap_sendpacket.restype  = c_int

    libpcap.pcap_lib_version.argtypes = [c_void_p]
    libpcap.pcap_lib_version.restype  = c_char_p

    libpcap.pcap_setdirection.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_setdirection.restype  = c_int

    libpcap.pcap_set_snaplen.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_set_snaplen.restype  = c_int

    libpcap.pcap_snapshot.argtypes = [POINTER(PCAP)]
    libpcap.pcap_snapshot.restype  = c_int

    libpcap.pcap_set_promisc.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_set_promisc.restype  = c_int

    libpcap.pcap_set_rfmon.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_set_rfmon.restype  = c_int

    libpcap.pcap_can_set_rfmon.argtypes = [POINTER(PCAP)]
    libpcap.pcap_can_set_rfmon.restype  = c_int

    libpcap.pcap_set_timeout.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_set_timeout.restype  = c_int

    libpcap.pcap_set_buffer_size.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_set_buffer_size.restype  = c_int

    libpcap.pcap_set_tstamp_type.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_set_tstamp_type.restype  = c_int

    libpcap.pcap_list_tstamp_types.argtypes = [POINTER(PCAP), POINTER(POINTER(c_int))]
    libpcap.pcap_list_tstamp_types.restype  = c_int

    libpcap.pcap_free_tstamp_types.argtypes = [POINTER(c_int)]
    libpcap.pcap_free_tstamp_types.restype  = None

    libpcap.pcap_tstamp_type_val_to_name.argtypes = [c_int]
    libpcap.pcap_tstamp_type_val_to_name.restype  = c_char_p

    libpcap.pcap_tstamp_type_val_to_description.argtypes = [c_int]
    libpcap.pcap_tstamp_type_val_to_description.restype  = c_int

    libpcap.pcap_tstamp_type_name_to_val.argtypes = [c_char_p]
    libpcap.pcap_tstamp_type_name_to_val.restype  = c_int

    libpcap.pcap_set_tstamp_precision.argtypes = [POINTER(PCAP), c_int]
    libpcap.pcap_set_tstamp_precision.restype  = c_int

    libpcap.pcap_get_tstamp_precision.argtypes = [POINTER(PCAP)]
    libpcap.pcap_get_tstamp_precision.restype  = c_int

    libpcap.pcap_datalink.argtypes = [POINTER(PCAP)]
    libpcap.pcap_datalink.restype  = c_int

    libpcap.pcap_is_swapped.argtypes = [POINTER(PCAP)]
    libpcap.pcap_is_swapped.restype  = c_int

    libpcap.pcap_stats.argtypes = [POINTER(PCAP), POINTER(PcapStat)]
    libpcap.pcap_stats.restype  = c_int

    libpcap.pcap_statustostr.argtypes = [c_int]
    libpcap.pcap_statustostr.restype  = c_char_p

    libpcap.pcap_dispatch.argtypes = [POINTER(PCAP), c_int, c_void_p ,c_char_p]
    libpcap.pcap_dispatch.restype  = c_int

    libpcap.pcap_open_dead.argtypes = [c_int, c_int]
    libpcap.pcap_open_dead.restype = PCAP

    libpcap.pcap_open_dead_with_tstamp_precision.argtypes = [
        c_int,
        c_int,
        c_uint
    ]
    libpcap.pcap_open_dead_with_tstamp_precision.restype  = PCAP

    # XXX: setup bpf_program struct
    # libpcap.pcap_setfilter.argtypes = [POINTER(PCAP),

    # libpcap.pcap_setfilter.restype  = c_int

    # XXX
    #libpcap.pcap_compile.argtypes = [
        #POINTER(PCAP),
        #POINTER(BPF),
        #c_char_p,
        #c_int,
        #c_int,
    #]
    #libpcap.pcap_compile.restype  =c_int

    #libpcap.pcap_offline_filter.argtypes = [
        #POINTER(BPF),
        #POINTER(PcapPkthd),
        #POINTER(Packet)
    #]
    #libpcap.pcap_offline_filter.restype  = c_int

    return libpcap

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




HANDLE_FUN = CFUNCTYPE(c_char_p, POINTER(PcapPkthd), c_char_p)

def handle_cb(a, b, c):
    print a, b, c
    return 0

handled_cb = HANDLE_FUN(handle_cb)
