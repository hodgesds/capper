import tornado.ioloop
from   capper._wrapper import Pcap
from   capper._libpcap import handled_cb
from   functools import partial

def pkt_handler(*args, **kwargs):
    import pdb
    pdb.set_trace()

def pcap_close(*args, **kwargs):
    print 'getting next packet'
    print args[0].loop(args[1], 15, handled_cb, None)
    args[0].activate(args[1])
    #print args[0].next_packet(args[1])


def shutdown(*args, **kwargs):
    args[0].close(args[1])
    tornado.ioloop.IOLoop.current().stop()

def main():
    pcap = Pcap()
    dev  = pcap.create(pcap.device)
    print 'using', pcap.device
    #can_mon = pcap.can_set_rfmon(dev)
    #print 'can mon:', can_mon
    #if can_mon == 0:
    #    print pcap.get_error(dev)
    #else:
    #    mon  = pcap.set_rfmon(dev, 1)
    #    print 'rf mon:', mon
    #to   = pcap.set_timeout(dev, 0)
    #print 'timeout', to
    #buff = pcap.set_buff_size(dev, 65535)
    #print 'buff size:', buff
    #snap = pcap.set_snaplen(dev, 65535)
    #print 'snap:', snap
    #prom = pcap.set_promisc(dev, 1)
    #print 'prom:', prom
    #act  = pcap.activate(dev)
    #print 'activated:', act
    nb   = pcap.set_nonblock(dev, 0)
    print "non block", nb
    fd   = pcap.get_fd(dev)
    print 'fd:', fd
    gnb  = pcap.get_nonblock(dev)
    print 'get nonblock', gnb
    ioloop = tornado.ioloop.IOLoop.instance()
    if fd > 0 and gnb > 0:
        ioloop.add_handler(fd, pkt_handler, ioloop.READ)
    ioloop.add_timeout(ioloop.time()+1, pcap_close, *(pcap, dev))
    ioloop.add_timeout(ioloop.time()+5, shutdown, *(pcap, dev))
    ioloop.start()

main()
