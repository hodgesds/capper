from ctypes import *
from platform import platform
from _libpcap import (
    load_libpcap,
    PcapPkthd,
    TimeVal,
    PCAP,
    PcapStat,
    PCAPIf
)

pf = platform()

class PcapExecption(Exception):
    pass

def setup_pcap():
    libpcap = load_libpcap()

    libpcap.pcap_lookupdev.argtypes = [c_char_p]
    libpcap.pcap_lookupdev.restype  = c_char_p

    libpcap.pcap_free_tstamp_types.argtypes = [POINTER(c_int)]
    libpcap.pcap_free_tstamp_types.restype  = None

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

    libpcap.pcap_next.argtypes = [c_int, POINTER(PcapPkthd)]
    libpcap.pcap_next.restype  = c_char

    libpcap.pcap_findalldevs.argtypes = [POINTER(POINTER(PCAPIf)), c_char_p]
    libpcap.pcap_findalldevs.restype  = c_int

    libpcap.pcap_freealldevs.argtypes = [POINTER(PCAPIf), c_char_p]
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
        POINTER(PcapPkthd),
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
    libpcap.pcap_list_tstamp_types.argtypes = c_int

    libpcap.pcap_free_tstamp_types.argtypes = [POINTER(PCAP), POINTER(POINTER(c_int))]
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

    return libpcap



def create_pcap():
    libpcap = setup_pcap()


class Pcap(object):
    def __init__(self, *args, **kwargs):
        self.libpcap = setup_pcap()

    @property
    def device(self):
        ebuff = c_char_p('x' * 255)
        dev   = self.libpcap.pcap_lookupdev(ebuff)
        if not dev:
            raise PcapExecption(ebuff)
        return dev

    def lookup_net(self, dev, net, mask):
        dev_p  = c_char_p(dev)
        net_p  = c_uint(net)
        mask_p = c_uint(mask)
        ebuff  = c_char_p('x' * 255)
        res    = self.libpcap.pcap_lookupnet(
            dev_p,
            net_p,
            mask_p,
            ebuff
        )
        if res == -1:
            raise PcapExecption(ebuff.value)
        return res

    def open(self, snaplen, promisc, to_ms):
        dev_p  = c_char_p(self.device)
        sn_p   = c_int(snaplen)
        prom_p = c_int(int(bool(promisc)))
        toms_p = c_int(to_ms)
        ebuff  = c_char_p('x' * 255)
        h      = self.libpcap.pcap_open_live(
            dev_p,
            sn_p,
            prom_p,
            toms_p,
            ebuff
        )
        if not h:
            raise PcapExecption(ebuff.value)
        self.handle = h

    def create(self, dev):
        dev_p = c_char_p(dev)
        ebuff = c_char_p('x' * 255)
        pcap  = self.libpcap.pcap_create(
            dev_p,
            ebuff
        )
        return pcap

    def close(self, pcap):
        self.libpcap.pcap_close(pcap)

    def activate(self, pcap):
        res = self.libpcap.pcap_activate(pcap)
        return res

    def next_packet(self):
        header = PcapPkthd()
        pkt    = self.libpcap.pcap_next(
            self.handle,
            header
        )
        return pkt

    def version(self):
        return self.libpcap.pcap_lib_version(None)

    def breakloop(self, pcap):
        self.libpcap.pcap_breakloop(pcap)

    #def loop(self, pcap, count, user):
    #    c_count = c_int(count)
    #    c_user  = c_char(user)
    #    self.libpcap.pcap_loop(pcap)
