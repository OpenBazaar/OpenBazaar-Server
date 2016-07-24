__author__ = 'chris'

import socket
import nacl.signing
import nacl.hash
import time
from config import SEEDS
from dht.node import Node
from dht.utils import digest
from interfaces import MessageProcessor, Multiplexer, ConnectionHandler
from log import Logger
from net.dos import BanScore
from protos.message import Message, PING, NOT_FOUND
from protos.objects import FULL_CONE
from random import shuffle
from twisted.internet import task, reactor
from twisted.internet.task import LoopingCall
from txrudp.connection import HandlerFactory, Handler, State
from txrudp.crypto_connection import CryptoConnectionFactory
from txrudp.rudp import ConnectionMultiplexer
from zope.interface.verify import verifyObject
from zope.interface import implements


class OpenBazaarProtocol(ConnectionMultiplexer):
    """
    A protocol extending the txrudp datagram protocol. This is the main protocol
    which gets passed into the twisted UDPServer. It handles the setup and tear down
    of all connections, parses messages coming off the wire and passes them off to
    the appropriate classes for processing.
    """
    implements(Multiplexer)

    def __init__(self, db, ip_address, nat_type, testnet=False, relaying=False):
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
        self.relay_node = None
        self.nat_type = nat_type
        self.vendors = db.vendors.get_vendors()
        self.ban_score = BanScore(self)
        self.factory = self.ConnHandlerFactory(self.processors, nat_type, self.relay_node, self.ban_score)
        self.log = Logger(system=self)
        self.keep_alive_loop = LoopingCall(self.keep_alive)
        self.keep_alive_loop.start(30, now=False)
        ConnectionMultiplexer.__init__(self, CryptoConnectionFactory(self.factory), self.ip_address[0], relaying)

    class ConnHandler(Handler):
        implements(ConnectionHandler)

        def __init__(self, processors, nat_type, relay_node, ban_score, *args, **kwargs):
            super(OpenBazaarProtocol.ConnHandler, self).__init__(*args, **kwargs)
            self.log = Logger(system=self)
            self.processors = processors
            self.connection = None
            self.node = None
            self.relay_node = relay_node
            self.ban_score = ban_score
            self.addr = None
            self.is_new_node = True
            self.on_connection_made()
            self.time_last_message = 0
            self.remote_node_version = 1
            self.ping_interval = 30 if nat_type != FULL_CONE else 300

        def on_connection_made(self):
            if self.connection is None or self.connection.state == State.CONNECTING:
                return task.deferLater(reactor, .1, self.on_connection_made)
            if self.connection.state == State.CONNECTED:
                self.addr = str(self.connection.dest_addr[0]) + ":" + str(self.connection.dest_addr[1])
                self.log.info("connected to %s" % self.addr)

        def receive_message(self, datagram):
            if len(datagram) < 166:
                self.log.warning("received datagram too small from %s, ignoring" % self.addr)
                return False
            try:
                m = Message()
                m.ParseFromString(datagram)
                self.node = Node(m.sender.guid,
                                 m.sender.nodeAddress.ip,
                                 m.sender.nodeAddress.port,
                                 m.sender.publicKey,
                                 None if not m.sender.HasField("relayAddress") else
                                 (m.sender.relayAddress.ip, m.sender.relayAddress.port),
                                 m.sender.natType,
                                 m.sender.vendor)
                self.remote_node_version = m.protoVer
                if self.time_last_message == 0:
                    h = nacl.hash.sha512(m.sender.publicKey)
                    pow_hash = h[40:]
                    if int(pow_hash[:6], 16) >= 50 or m.sender.guid.encode("hex") != h[:40]:
                        raise Exception('Invalid GUID')
                for processor in self.processors:
                    if m.command in processor or m.command == NOT_FOUND:
                        processor.receive_message(m, self.node, self.connection, self.ban_score)
                if m.command != PING:
                    self.time_last_message = time.time()
            except Exception:
                # If message isn't formatted property then ignore
                self.log.warning("received an invalid message from %s, ignoring" % self.addr)
                return False

        def handle_shutdown(self):
            try:
                self.connection.unregister()
            except Exception:
                pass

            if self.node is None:
                self.node = Node(digest("null"), str(self.connection.dest_addr[0]),
                                 int(self.connection.dest_addr[1]))
            for processor in self.processors:
                processor.timeout(self.node)

            if self.addr:
                self.log.info("connection with %s terminated" % self.addr)

            if self.relay_node == (self.connection.dest_addr[0], self.connection.dest_addr[1]):
                self.log.info("Disconnected from relay node. Picking new one...")
                self.change_relay_node()

        def keep_alive(self):
            """
            Let's check that this node has been active in the last 5 minutes. If not
            and if it's not in our routing table, we don't need to keep the connection
            open. Otherwise PING it to make sure the NAT doesn't drop the mapping.
            """
            t = time.time()
            router = self.processors[0].router
            if (
                    self.node is not None and
                    t - self.time_last_message >= 300 and
                    router.isNewNode(self.node) and
                    self.relay_node != (self.connection.dest_addr[0], self.connection.dest_addr[1])
            ):
                self.connection.shutdown()
                return

            if t - self.time_last_message >= self.ping_interval:
                for processor in self.processors:
                    if PING in processor and self.node is not None:
                        processor.callPing(self.node)

        def change_relay_node(self):
            potential_relay_nodes = []
            for bucket in self.processors[0].router.buckets:
                for node in bucket.nodes.values():
                    if node.nat_type == FULL_CONE:
                        potential_relay_nodes.append((node.ip, node.port))
            if len(potential_relay_nodes) == 0:
                for seed in SEEDS:
                    try:
                        potential_relay_nodes.append((socket.gethostbyname(seed[0].split(":")[0]),
                                                      28469 if self.processors[0].TESTNET else 18469))
                    except socket.gaierror:
                        pass
            shuffle(potential_relay_nodes)
            self.relay_node = potential_relay_nodes[0]
            for processor in self.processors:
                if PING in processor:
                    if (self.relay_node[0], self.relay_node[1]) in processor.multiplexer:
                        processor.multiplexer[(self.relay_node[0], self.relay_node[1])].shutdown()
                    processor.callPing(Node(digest("null"), self.relay_node[0], self.relay_node[1],
                                            relay_node=None, nat_type=FULL_CONE))

        def check_new_connection(self):
            if self.is_new_node:
                self.is_new_node = False
                return True
            else:
                return False

    class ConnHandlerFactory(HandlerFactory):

        def __init__(self, processors, nat_type, relay_node, ban_score):
            super(OpenBazaarProtocol.ConnHandlerFactory, self).__init__()
            self.processors = processors
            self.nat_type = nat_type
            self.relay_node = relay_node
            self.ban_score = ban_score

        def make_new_handler(self, *args, **kwargs):
            return OpenBazaarProtocol.ConnHandler(self.processors, self.nat_type, self.relay_node, self.ban_score)

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

    def keep_alive(self):
        for connection in self.values():
            if connection.state == State.CONNECTED:
                connection.handler.keep_alive()

    def send_message(self, datagram, address, relay_addr):
        """
        Sends a datagram over the wire to the given address. It will create a new rudp connection if one
        does not already exist for this peer.

        Args:
            datagram: the raw data to send over the wire
            address: a `tuple` of (ip address, port) of the recipient.
            relay_addr: a `tuple` of (ip address, port) of the relay address
                or `None` if no relaying is required.
        """
        if address not in self:
            con = self.make_new_connection(self.ip_address, address, relay_addr)
        else:
            con = self[address]
        if relay_addr is not None and relay_addr != con.relay_addr and relay_addr != con.own_addr:
            con.set_relay_address(relay_addr)

        con.send_message(datagram)
