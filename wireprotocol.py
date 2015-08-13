__author__ = 'chris'
from zope.interface.verify import verifyObject
from txrudp.rudp import ConnectionMultiplexer
from txrudp.connection import HandlerFactory, Handler
from txrudp.crypto_connection import CryptoConnectionFactory
from interfaces import MessageProcessor
from protos.message import Message
from log import Logger


class OpenBazaarProtocol(ConnectionMultiplexer):
    def __init__(self, ip_address):
        """
        Initialize the new protocol with the connection handler factory.

        Args:
                ip_address: a `tuple` of the (ip address, port) of ths node.
        """
        self.ip_address = ip_address
        self.processors = []
        self.factory = self.ConnHandlerFactory(self.processors)
        ConnectionMultiplexer.__init__(self, CryptoConnectionFactory(self.factory), self.ip_address[0])

    class ConnHandler(Handler):

        def __init__(self, processors, *args, **kwargs):
            super(OpenBazaarProtocol.ConnHandler, self).__init__(*args, **kwargs)
            self.log = Logger(system=self)
            self.processors = processors
            self.connection = None

        def receive_message(self, datagram):
            if len(datagram) < 166:
                self.log.warning("received datagram too small from %s, ignoring" % str(self.connection.dest_addr))
                return False
            m = Message()
            try:
                m.ParseFromString(datagram)
                for processor in self.processors:
                    if m.command in processor:
                        processor.receive_message(datagram, self.connection)
            except Exception:
                # If message isn't formatted property then ignore
                self.log.warning("Received unknown message from %s, ignoring" % str(self.connection.dest_addr))
                return False

        def handle_shutdown(self):
            self.log.info(
                "Connection with (%s, %s) terminated" % (self.connection.dest_addr[0],
                                                         self.connection.dest_addr[1]))

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
