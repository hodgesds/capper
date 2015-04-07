import tornado.ioloop
import tornado.web
from   tornado import websocket
from   capper._wrapper import Pcap
from   capper._libpcap import handled_cb, CallbackHandler
from   functools import partial


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('''
        <script>
        var ws = new WebSocket("ws://167.88.36.11:8888/ws");
        ws.onopen = function() {
               ws.send("Hello, world");
        };
        ws.onmessage = function (evt) {
               console.log(evt.data);
        };
        </script>
        ''')

class EchoWebSocket(websocket.WebSocketHandler):
    def open(self):
        print "WebSocket opened"
        clients.append(self)

    def on_message(self, message):
        self.write_message(u"You said: " + message)

    def on_close(self):
        print "WebSocket closed"


def read_fd(fd, *args, **kwargs):
    dev  = kwargs.get('dev')
    pcap = kwargs.get('pcap')
    cbh  = kwargs.get('cbh')
    res  = pcap.dispatch(dev, 1, cbh.cb, None)
    ws   = kwargs.get('ws')
    if len(cbh.q) > 0:
        pkt_hdr, pkt = cbh.q.popleft()
        for c in clients:
            c.write_message(pkt)

def shutdown(*args, **kwargs):
    args[0].close(args[1])
    tornado.ioloop.IOLoop.current().stop()

clients = []

def main():
    # add web handler
    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/ws", EchoWebSocket),
    ])
    application.listen(8888)
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
    act  = pcap.activate(dev)
    print 'activated:', act
    nb   = pcap.set_nonblock(dev, 1)
    print "non block", nb
    fd   = pcap.get_fd(dev)
    print 'fd:', fd
    gnb  = pcap.get_nonblock(dev)
    print 'get nonblock', gnb
    cbh = CallbackHandler()
    ioloop = tornado.ioloop.IOLoop.instance()
    if fd > 0 and gnb > 0:
        read_partial = partial(read_fd, **{'dev':dev, 'pcap':pcap, 'cbh':cbh})
        ioloop.add_handler(fd, read_partial, ioloop.READ)
    #ioloop.add_timeout(ioloop.time()+5, shutdown, *(pcap, dev))
    ioloop.start()

main()
