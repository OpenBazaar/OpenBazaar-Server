__author__ = 'chris'
from zope.interface.verify import verifyObject
from txrudp.rudp import ConnectionMultiplexer
from txrudp.connection import HandlerFactory, Handler, State
from txrudp.crypto_connection import CryptoConnectionFactory
from twisted.internet.task import LoopingCall
from twisted.internet import task, reactor
from interfaces import MessageProcessor
from protos.message import Message
from log import Logger
from dht.node import Node
from protos.message import PING, NOT_FOUND


class OpenBazaarProtocol(ConnectionMultiplexer):
    """
    A protocol extending the txrudp datagram protocol. This is the main protocol
    which gets passed into the twisted UDPServer. It handles the setup and tear down
    of all connections, parses messages coming off the wire and passes them off to
    the appropriate classes for processing.
    """

    def __init__(self, ip_address, testnet=False):
        """
        Initialize the new protocol with the connection handler factory.

        Args:
                ip_address: a `tuple` of the (ip address, port) of ths node.
        """
        self.ip_address = ip_address
        self.testnet = testnet
        self.ws = None
        self.blockchain = None
        self.processors = []
        self.factory = self.ConnHandlerFactory(self.processors)
        self.log = Logger(system=self)
        ConnectionMultiplexer.__init__(self, CryptoConnectionFactory(self.factory), self.ip_address[0])

    class ConnHandler(Handler):

        def __init__(self, processors, *args, **kwargs):
            super(OpenBazaarProtocol.ConnHandler, self).__init__(*args, **kwargs)
            self.log = Logger(system=self)
            self.processors = processors
            self.connection = None
            self.node = None
            self.keep_alive_loop = LoopingCall(self.keep_alive)
            self.keep_alive_loop.start(300, now=False)
            self.on_connection_made()
            self.addr = None

        def on_connection_made(self):
            if self.connection is None or self.connection.state == State.CONNECTING:
                return task.deferLater(reactor, 1, self.on_connection_made)
            if self.connection.state == State.CONNECTED:
                self.addr = str(self.connection.dest_addr[0]) + ":" + str(self.connection.dest_addr[1])
                self.log.info("connected to %s" % self.addr)

        def receive_message(self, datagram):
            if len(datagram) < 166:
                self.log.warning("received datagram too small from %s, ignoring" % self.addr)
                return False
            m = Message()
            try:
                m.ParseFromString(datagram)
                self.node = Node(m.sender.guid, m.sender.ip, m.sender.port,
                                 m.sender.signedPublicKey, m.sender.vendor)
                for processor in self.processors:
                    if m.command in processor or m.command == NOT_FOUND:
                        processor.receive_message(datagram, self.connection)
            except Exception:
                # If message isn't formatted property then ignore
                self.log.warning("received unknown message from %s, ignoring" % self.addr)
                return False

        def handle_shutdown(self):
            for processor in self.processors:
                processor.timeout((self.connection.dest_addr[0], self.connection.dest_addr[1]), self.node)
            reactor.callLater(90, self.connection.unregister)
            if self.addr:
                self.log.info("connection with %s terminated" % self.addr)
            try:
                self.keep_alive_loop.stop()
            except Exception:
                pass

        def keep_alive(self):
            for processor in self.processors:
                if PING in processor and self.node is not None:
                    processor.callPing(self.node)

    class ConnHandlerFactory(HandlerFactory):

        def __init__(self, processors):
            super(OpenBazaarProtocol.ConnHandlerFactory, self).__init__()
            self.processors = processors

        def make_new_handler(self, *args, **kwargs):
            return OpenBazaarProtocol.ConnHandler(self.processors)

    def register_processor(self, processor):
        """Add a new class which implements the `MessageProcessor` interface."""
        if verifyObject(MessageProcessor, processor):
            self.processors.append(processor)

    def unregister_processor(self, processor):
        """Unregister the given processor."""
        if processor in self.processors:
            self.processors.remove(processor)

    def set_servers(self, ws, blockchain):
        self.ws = ws
        self.blockchain = blockchain

    def send_message(self, datagram, address):
        """
        Sends a datagram over the wire to the given address. It will create a new rudp connection if one
        does not already exist for this peer.

        Args:
            datagram: the raw data to send over the wire
            address: a `tuple` of (ip address, port) of the recipient.
        """
        if address not in self:
            con = self.make_new_connection((self.ip_address[0], self.ip_address[1]), address)
        else:
            con = self[address]
        con.send_message(datagram)

