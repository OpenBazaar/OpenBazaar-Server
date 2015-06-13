__author__ = 'chris'

"""
This is an unfinished outline of a class which extends txrudp for use in a
twisted UDPServer. When txrudp is finished we can add our custom messages in here.
"""

import abc

from txrudp.rudp import ConnectionMultiplexer
from txrudp.connection import RUDPConnectionFactory
from txrudp.connection import HandlerFactory, Handler

from dht.log import Logger

from twisted.internet import protocol

class MerchantProtocol(ConnectionMultiplexer):

    def __init__(self, public_ip):
        self.public_ip = public_ip
        self.log = Logger(system=self)
        self.handler_factory = MerchantProtocolHandlerFactory()
        self.connection_factory = RUDPConnectionFactory(self.handler_factory)

        ConnectionMultiplexer.__init__(self, self.connection_factory, public_ip)

    def send(self, datagram, addr):
        connection = self.make_new_connection( self.public_ip, addr, None)
        connection.send_message(datagram)
        connection.shtdown()


class MerchantProtocolHandlerFactory(HandlerFactory):
    def __init__(self, *args, **kwargs):
        """Create a new HandlerFactory."""

    def make_new_handler(self, *args, **kwargs):
        return MerchantProtocolHandler(args)

class MerchantProtocolHandler(Handler):
    __metaclass__ = abc.ABCMeta

    connection = None

    def __init__(self, args):
        self.own_addr = args[0]
        self.source_addr = args[1]
        self.relay_addr = args[2]

    def receive_message(self, message):
        """
        Receive a message from the given connection.
        Args:
            message: The payload of an RUDPPacket, as a string.
        """
        # We will need to parse the message to determine the type then do
        # something with it.

    def handle_shutdown(self):
        """Handle connection shutdown."""