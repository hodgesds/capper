import ctypes.util
from   ctypes import *
from   platform import platform
from   _libpcap import (
    load_libpcap,
    PcapPkthd,
    TimeVal,
    PCAP,
    PcapStat,
    PcapIf,
    setup_libpcap,
)

clib      = cdll.LoadLibrary(ctypes.util.find_library("c"))
c_int_p   = POINTER(c_int)
c_ubyte_p = POINTER(c_byte)
pf        = platform()


class PcapException(Exception):
    pass


class Pcap(object):
    def __init__(self, *args, **kwargs):
        self.libpcap = setup_libpcap()

    @property
    def device(self):
        ebuff = c_char_p('')
        dev   = self.libpcap.pcap_lookupdev(ebuff)
        if not dev:
            raise PcapException(ebuff)
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
            raise PcapException(ebuff.value)
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
            raise PcapException(ebuff.value)
        self.handle = h

    def create(self, dev="any"):
        dev_p = c_char_p(dev)
        ebuff = c_char_p('')
        pcap  = self.libpcap.pcap_create(
            dev_p,
            ebuff
        )
        if ebuff.value:
            print ebuff.value
            raise PcapException(ebuff.value)
        return pcap

    def close(self, pcap):
        self.libpcap.pcap_close(pcap)

    def activate(self, pcap):
        res = self.libpcap.pcap_activate(pcap)
        return res

    def set_snaplen(self, pcap, snaplen):
        snap_c = c_int(snaplen)
        res    = self.libpcap.pcap_set_snaplen(pcap, snap_c)
        if res !=0 :
            raise PcapException("{0} ACTIVATED".format(pcap))
        return res

    def get_snaplen(self, pcap):
        snaplen = self.libpcap.pcap_snapshot(pcap)
        return snaplen

    def set_timeout(self, pcap, to):
        to_c = c_int(to)
        to   = self.libpcap.pcap_set_timeout(pcap, to_c)
        if to != 0:
            raise PcapException("{0} ACTIVATED".format(pcap))
        return to

    def set_promisc(self, pcap, prom):
        prom_int_c = c_int(prom)
        err        = self.libpcap.pcap_set_promisc(pcap, prom_int_c)
        if err != 0:
            print self.get_error(pcap)
        return err

    def next_packet(self, pcap):
        header = PcapPkthd()
        pkt    = self.libpcap.pcap_next(
            pcap,
            header
        )
        return pkt, header

    @property
    def version(self):
        return self.libpcap.pcap_lib_version(None)

    def breakloop(self, pcap):
        self.libpcap.pcap_breakloop(pcap)

    def loop(self, pcap, count, cb, user):
        c_count = c_int(count)
        c_user  = c_char_p(user)
        ret     = self.libpcap.pcap_loop(pcap, c_count, cb, c_user)
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

    def get_error(self, pcap):
        return self.libpcap.pcap_geterr(pcap)

    def free_devices(self):
        devs  = self.devices
        ebuff =  c_char_p('')
        self.libpcap.pcap_freealldevs(
            devs,
            ebuff,
        )
        if ebuff.value:
            raise PcapException(ebuff.value)

    def set_nonblock(self, pcap, nb):
        nb_c  = c_int(nb)
        ebuff =  c_char_p(' '*256)
        res   = self.libpcap.pcap_setnonblock(
            pcap,
            nb_c,
            ebuff
        )
        if res == -1:
            raise PcapException(ebuff.value)
        return res

    def get_nonblock(self, pcap):
        ebuff =  c_char_p(' '*256)
        res   = self.libpcap.pcap_getnonblock(
            pcap,
            ebuff
        )
        if res == -1:
            raise PcapException(ebuff.value)
        return res

    def inject(self, pcap, pkt):
        pkt_c     = c_char_p(pkt)
        pkt_len_c = c_int(sizeof(pkt))
        res = self.libpcap.pcap_inject(
            pcap,
            cast(pkt_c, c_void_p),
            pkt_len_c
        )
        if res != 0:
            raise PcapException("Failed to write packet {0}".format(pkt))

    def sendpacket(self, pcap, pkt):
        pkt_c     = c_char_p(pkt)
        pkt_len_c = c_int(sizeof(pkt))
        self.libpcap.pcap_sendpacket(
            pcap,
            pkt_c,
            pkt_len_c
        )

    def stamp_types(self, pcap):
        icp = POINTER(c_int_p)()
        res = self.libpcap.pcap_list_tstamp_types(
            pcap,
            icp
        )
        # could we get any stamp types?
        if res == 0:
            #self.libpcap.pcap_free_tstamp_types(icp)
            return icp
        return icp

    def stamp_name(self, stamp):
        name = self.libpcap.pcap_tstamp_type_val_to_name(stamp)
        if not name:
            raise PcapException('Stamp name {0} name not found'.format(stamp))
        return name.value

    def stamp_desc(self, stamp):
        desc = self.libpcap.pcap_tstamp_type_val_to_description(stamp)
        if not desc:
            raise PcapException(
                'Stamp description {0} name not found'.format(stamp)
            )
        return name.value

    def free_stamp(self, stamp):
        self.libpcap.pcap_free_tstamp_types(c_int_p)

    def datalink(self, pcap):
        return self.libpcap.pcap_datalink(pcap)

    def can_set_rfmon(self, pcap):
        rfmon = self.libpcap.pcap_can_set_rfmon(pcap)
        if rfmon == 0:
            err = self.libpcap.pcap_geterr(pcap)
            print err
        return rfmon

    def set_rfmon(self, pcap, mon):
        mon_c = c_int(mon)
        res = self.libpcap.pcap_set_rfmon(pcap, mon_c)
        return res

    def get_fd(self, pcap):
        fd = self.libpcap.pcap_get_selectable_fd(pcap)
        return fd

    def dead(self, link, snaplen):
        link_c = c_int(link)
        snap_c = c_int(snaplen)
        dev   = self.libpcap.pcap_open_dead(link_c, snap_c)
        return dev

    def set_buff_size(self, pcap, buff_len):
        c_buff = c_int(buff_len)
        buff = self.libpcap.pcap_set_buffer_size(pcap, c_buff)
        return buff

    def is_swapped(self, pcap):
        return self.libpcap.pcap_is_swapped(pcap)
