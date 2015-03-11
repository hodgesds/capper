import tornado.ioloop
from capper._wrapper import Pcap


def pkt_handler(*args, **kwargs):
    import pdb
    pdb.set_trace()

def main():
    pcap = Pcap()
    dev  = pcap.create(pcap.device)
    nb   = pcap.set_nonblock(dev, 1)
    print "non block", nb
    gnb  = pcap.get_nonblock(dev)
    print 'get nonblock', gnb
    can_mon = pcap.can_set_rfmon(dev)
    print 'can mon:', can_mon
    if can_mon == 0:
        print pcap.get_error(dev)
    else:
        mon  = pcap.set_rfmon(dev, 1)
        print 'rf mon:', mon
    to   = pcap.set_timeout(dev, 10000)
    print 'timeout', to
    buff = pcap.set_buff_size(dev, 2048)
    print 'buff size:', buff
    snap = pcap.set_snaplen(dev, 65535)
    print 'snap:', snap
    act  = pcap.activate(dev)
    err  = pcap.get_error(dev)
    print 'err:', err
    print 'activated:', act
    fd   = pcap.get_fd(dev)
    print 'fd:', fd
    ioloop = tornado.ioloop.IOLoop.instance()
    ioloop.add_handler(fd, pkt_handler, ioloop.READ)
    ioloop.start()

main()
