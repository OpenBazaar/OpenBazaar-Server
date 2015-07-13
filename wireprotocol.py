__author__ = 'chris'
from txrudp.rudp import ConnectionMultiplexer
from txrudp.connection import HandlerFactory, Handler, ConnectionFactory

from interfaces import MessageProcessor

from zope.interface.verify import verifyObject

from dht.kprotocol import Message
from dht.log import Logger

class OpenBazaarProtocol(ConnectionMultiplexer):
    def __init__(self, ip_address, processors=None):
        """
        Initialize the new protocol with the connection handler factory.

        Args:
                ip_address: a `tuple` of the (ip address, port) of ths node.
                processors: a `list` of classes implementing the `MessageProcessor` interface. Classes
                            can also be added later using the register_processor method.
        """
        self.factory = self.ConnHandlerFactory()
        self.ip = ip_address[0]
        self.port = ip_address[1]
        self.processors = []
        if processors is not None:
                for processor in processors:
                    if verifyObject(MessageProcessor, processor):
                        self.processors.append(processors)
        self.factory = self.ConnHandlerFactory(self.processors)
        ConnectionMultiplexer.__init__(self, ConnectionFactory(self.factory), ip_address)

    class ConnHandler(Handler):

        def __init__(self, procssors):
            self.log = Logger(system=self)
            self.processors = procssors
            self.connection = None

        def receive_message(self, datagram):
            if len(datagram) < 22:
                self.log.msg("received datagram too small from %s, ignoring" % repr(self.connection.dest_addr))
                return False

            m = Message()
            try:
                m.ParseFromString(datagram)
                command = m.command
                for processor in self.processors:
                    if command in processor:
                        processor.receive_message(datagram, self.connection)
            except:
                # If message isn't formatted property then ignore
                self.log.msg("Received unknown message from %s, ignoring" % repr(self.connection.dest_addr))
                return False

    class ConnHandlerFactory(HandlerFactory):

        def __init__(self, processors):
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
                con = self.make_new_connection((self.ip, self.port), address)
        else:
                con = self[address]
        con.send_message(datagram)