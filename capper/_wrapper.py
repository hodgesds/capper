from ctypes import *
import ctypes.util
from platform import platform
clib = cdll.LoadLibrary(ctypes.util.find_library("c"))
from _libpcap import (
    load_libpcap,
    PcapPkthd,
    TimeVal,
    PCAP,
    PcapStat,
    PcapIf
)

c_int_p   = POINTER(c_int)
c_ubyte_p = POINTER(c_byte)
pf = platform()

class PcapExecption(Exception):
    pass

def setup_pcap():
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


def create_pcap():
    libpcap = setup_pcap()


class Pcap(object):
    def __init__(self, *args, **kwargs):
        self.libpcap = setup_pcap()

    @property
    def device(self):
        ebuff = c_char_p('')
        dev   = self.libpcap.pcap_lookupdev(ebuff)
        if not dev:
            raise PcapExecption(ebuff)
        return dev

    def lookup_net(self, dev, net, mask):
        dev_p  = c_char_p(dev)
        net_p  = c_uint(net)
        mask_p = c_uint(mask)
        ebuff  = c_char_p('')
        res    = self.libpcap.pcap_lookupnet(
            dev_p,
            net_p,
            mask_p,
            ebuff
        )
        if res == -1:
            raise PcapExecption(ebuff.value)
        return res

    def open(self, dev, snaplen, promisc, to_ms):
        dev_p  = c_char_p(dev)
        sn_p   = c_int(snaplen)
        prom_p = c_int(int(bool(promisc)))
        toms_p = c_int(to_ms)
        ebuff  = c_char_p('')
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
        ebuff = c_char_p('')
        pcap  = self.libpcap.pcap_create(
            dev_p,
            ebuff
        )
        if ebuff.value:
            print ebuff.value
            raise PcapExecption(ebuff.value)
        return pcap

    def close(self, pcap):
        self.libpcap.pcap_close(pcap)

    def activate(self, pcap):
        res = self.libpcap.pcap_activate(pcap)
        return res

    def next_packet(self, pcap):
        header = PcapPkthd()
        pkt    = self.libpcap.pcap_next(
            pcap,
            header
        )
        return pkt

    @property
    def version(self):
        return self.libpcap.pcap_lib_version(None)

    def breakloop(self, pcap):
        self.libpcap.pcap_breakloop(pcap)

    def loop(self, pcap, count, cb, user):
        c_count = c_int(count)
        c_user  = c_char_p(user)
        ret = self.libpcap.pcap_loop(pcap, c_count, cb, c_user)
        return ret

    @property
    def devices(self):
        devs  = POINTER(PcapIf)()
        ebuff = c_char_p('')
        self.libpcap.pcap_findalldevs(
            byref(devs),
            ebuff
        )
        return devs

    def free_devices(self):
        devs  = self.devices
        ebuff =  c_char_p('')
        self.libpcap.pcap_freealldevs(
            devs,
            ebuff,
        )
        if ebuff.value:
            raise PcapExecption(ebuff.value)

    def set_nonblock(self, pcap, nb):
        nb_c  = c_int(nb)
        ebuff =  c_char_p('')
        res   = self.libpcap.pcap_setnonblock(
            pcap,
            nb_c,
            ebuff
        )
        if res == -1:
            raise PcapExecption(ebuff.value)
        return res

    def get_nonblock(self, pcap):
        ebuff =  c_char_p('')
        res   = self.libpcap.pcap_getnonblock(
            pcap,
            ebuff
        )
        if res == -1:
            raise PcapExecption(ebuff.value)
        return res

    def inject(self, pcap, pkt):
        pkt_c     = c_char_p(pkt)
        pkt_len_c = c_int(len(pkt))
        res = self.libpcap.pcap_inject(
            pcap,
            cast(pkt_c, c_void_p),
            pkt_len_c
        )
        if res != 0:
            raise PcapExecption("Failed to write packet {0}".format(pkt))

    def sendpacket(self, pcap, pkt):
        pkt_c     = c_char_p(pkt)
        pkt_len_c = c_int(len(pkt))
        self.libpcap.pcap_sendpacket(
            pcap,
            pkt_c,
            pkt_len_c
        )

    def stamp_types(self, pcap):
        int_c_p = POINTER(c_int)()
        res = self.libpcap.pcap_list_tstamp_types(
            pcap,
            byref(int_c_p)
        )
        # could we get any stamp types?
        if res == 0:
            self.libpcap.pcap_free_tstamp_types(c_int_p)
            return None
        return int_c_p

    def stamp_name(self, stamp):
        name = self.libpcap.pcap_tstamp_type_val_to_name(stamp)
        if not name:
            raise PcapExecption('Stamp name {0} name not found'.format(stamp))
        return name.value

    def stamp_desc(self, stamp):
        desc = self.libpcap.pcap_tstamp_type_val_to_description(stamp)
        if not desc:
            raise PcapExecption(
                'Stamp description {0} name not found'.format(stamp)
            )
        return name.value

    def free_stamp(self, stamp):
        self.libpcap.pcap_free_tstamp_types(c_int_p)

    def datalink(self, pcap):
        return self.libpcap.pcap_datalink(pcap)

    def can_set_rfmon(self, pcap):
        return self.libpcap.pcap_can_set_rfmon(pcap)
