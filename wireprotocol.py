__author__ = 'chris'
from zope.interface.verify import verifyObject
from txrudp.rudp import ConnectionMultiplexer
from txrudp.connection import HandlerFactory, Handler
from txrudp.crypto_connection import CryptoConnectionFactory
from twisted.internet.task import LoopingCall
from interfaces import MessageProcessor
from protos.message import Message, FIND_VALUE
from log import Logger
from dht.node import Node
from protos.message import PING

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
        self.factory = self.ConnHandlerFactory(self.processors, self)
        ConnectionMultiplexer.__init__(self, CryptoConnectionFactory(self.factory), self.ip_address[0])

    class ConnHandler(Handler):

        def __init__(self, processors, active_connections, *args, **kwargs):
            super(OpenBazaarProtocol.ConnHandler, self).__init__(*args, **kwargs)
            self.log = Logger(system=self)
            self.processors = processors
            self.active_connections = active_connections
            self.connection = None
            self.node = None
            LoopingCall(self.ping).start(300, now=False)

            # TODO: should send ping message at regular intervals to catch an improperly closed connection.

        def receive_message(self, datagram):
            if len(datagram) < 166:
                self.log.warning("received datagram too small from %s, ignoring" % str(self.connection.dest_addr))
                return False
            m = Message()
            try:
                m.ParseFromString(datagram)
                self.node = Node(m.sender.guid, m.sender.ip, m.sender.port,
                                 m.sender.signedPublicKey, m.sender.vendor)
                for processor in self.processors:
                    if m.command in processor:
                        processor.receive_message(datagram, self.connection)
            except Exception:
                # If message isn't formatted property then ignore
                self.log.warning("Received unknown message from %s, ignoring" % str(self.connection.dest_addr))
                return False

        def handle_shutdown(self):
            self.connection.unregister()
            if self.node is not None:
                for processor in self.processors:
                    if FIND_VALUE in processor:
                        processor.router.removeContact(self.node)
            self.log.info(
                "Connection with (%s, %s) terminated" % (self.connection.dest_addr[0],
                                                         self.connection.dest_addr[1]))

        def ping(self):
            for processor in self.processors:
                if PING in processor:
                    processor.callPing(self.node)


    class ConnHandlerFactory(HandlerFactory):

        def __init__(self, processors, active_connections):
            super(OpenBazaarProtocol.ConnHandlerFactory, self).__init__()
            self.processors = processors
            self.active_connecitons = active_connections

        def make_new_handler(self, *args, **kwargs):
            return OpenBazaarProtocol.ConnHandler(self.processors, self.active_connecitons)

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

