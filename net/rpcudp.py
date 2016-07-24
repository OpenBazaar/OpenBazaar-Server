"""
Copyright (c) 2014 Brian Muller
Copyright (c) 2015 OpenBazaar
"""

import abc
import random
from base64 import b64encode
from config import PROTOCOL_VERSION
from dht.node import Node
from dht.utils import digest
from hashlib import sha1
from log import Logger
from protos.message import Message, Command, NOT_FOUND, HOLE_PUNCH
from protos.objects import FULL_CONE, RESTRICTED, SYMMETRIC
from twisted.internet import defer, reactor
from txrudp.connection import State


class RPCProtocol:
    """
    This is an abstract class for processing and sending rpc messages.
    A class that implements the `MessageProcessor` interface probably should
    extend this as it does most of the work of keeping track of messages.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, sourceNode, router, waitTimeout=30):
        """
        Args:
            sourceNode: A protobuf `Node` object containing info about this node.
            router: A `RoutingTable` object from dht.routing. Implies a `network.Server` object
                    must be started first.
            waitTimeout: Timeout for whole messages. Note the txrudp layer has a per-packet
                    timeout but invalid responses wont trigger it. The waitTimeout on this
                     layer needs to be long enough to allow whole messages (ex. images) to
                     transmit.

        """
        self.sourceNode = sourceNode
        self.router = router
        self._waitTimeout = waitTimeout
        self._outstanding = {}
        self.log = Logger(system=self)

    def receive_message(self, message, sender, connection, ban_score):
        if message.testnet != self.multiplexer.testnet:
            self.log.warning("received message from %s with incorrect network parameters." %
                             str(connection.dest_addr))
            connection.shutdown()
            return False

        if sender.vendor:
            self.multiplexer.vendors[sender.id] = sender

        msgID = message.messageID
        if message.command == NOT_FOUND:
            data = None
        else:
            data = tuple(message.arguments)
        if msgID in self._outstanding:
            self._acceptResponse(msgID, data, sender)
        elif message.command != NOT_FOUND:
            ban_score.process_message(connection.dest_addr, message)
            self._acceptRequest(msgID, str(Command.Name(message.command)).lower(), data, sender, connection)


    def _acceptResponse(self, msgID, data, sender):
        if data is not None:
            msgargs = (b64encode(msgID), sender)
            self.log.debug("received response for message id %s from %s" % msgargs)
        else:
            self.log.warning("received 404 error response from %s" % sender)
        d = self._outstanding[msgID][0]
        if self._outstanding[msgID][2].active():
            self._outstanding[msgID][2].cancel()
        d.callback((True, data))
        del self._outstanding[msgID]

    def _acceptRequest(self, msgID, funcname, args, sender, connection):
        self.log.debug("received request from %s, command %s" % (sender, funcname.upper()))
        f = getattr(self, "rpc_%s" % funcname, None)
        if f is None or not callable(f):
            msgargs = (self.__class__.__name__, funcname)
            self.log.error("%s has no callable method rpc_%s; ignoring request" % msgargs)
            return False
        if funcname == "hole_punch":
            f(sender, *args)
        else:
            d = defer.maybeDeferred(f, sender, *args)
            d.addCallback(self._sendResponse, funcname, msgID, sender, connection)
            d.addErrback(self._sendResponse, "bad_request", msgID, sender, connection)

    def _sendResponse(self, response, funcname, msgID, sender, connection):
        self.log.debug("sending response for msg id %s to %s" % (b64encode(msgID), sender))
        m = Message()
        m.messageID = msgID
        m.sender.MergeFrom(self.sourceNode.getProto())
        m.protoVer = PROTOCOL_VERSION
        m.testnet = self.multiplexer.testnet
        if response is None:
            m.command = NOT_FOUND
        else:
            m.command = Command.Value(funcname.upper())
            if not isinstance(response, list):
                response = [response]
            for arg in response:
                m.arguments.append(str(arg))
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        connection.send_message(m.SerializeToString())

    def timeout(self, node):
        """
        This timeout is called by the txrudp connection handler. We will run through the
        outstanding messages and callback false on any waiting on this IP address.
        """
        address = (node.ip, node.port)
        for msgID, val in self._outstanding.items():
            if address == val[1]:
                val[0].callback((False, None))
                if self._outstanding[msgID][2].active():
                    self._outstanding[msgID][2].cancel()
                del self._outstanding[msgID]

        self.router.removeContact(node)
        try:
            self.multiplexer[address].shutdown()
        except Exception:
            pass

    def rpc_hole_punch(self, sender, ip, port, relay="False"):
        """
        A method for handling an incoming HOLE_PUNCH message. Relay the message
        to the correct node if it's not for us. Otherwise send a datagram to allow
        the other node to punch through our NAT.
        """
        if relay == "True":
            self.log.debug("relaying hole punch packet to %s:%s for %s:%s" %
                           (ip, port, sender.ip, str(sender.port)))
            self.hole_punch(Node(digest("null"), ip, int(port), nat_type=FULL_CONE), sender.ip, sender.port)
        else:
            self.log.debug("punching through NAT for %s:%s" % (ip, port))
            # pylint: disable=W0612
            for i in range(20):
                self.multiplexer.send_datagram("", (ip, int(port)))

    def __getattr__(self, name):
        if name.startswith("_") or name.startswith("rpc_"):
            return object.__getattr__(self, name)

        try:
            return object.__getattr__(self, name)
        except AttributeError:
            pass

        def func(node, *args):
            address = (node.ip, node.port)

            msgID = sha1(str(random.getrandbits(255))).digest()
            m = Message()
            m.messageID = msgID
            m.sender.MergeFrom(self.sourceNode.getProto())
            m.command = Command.Value(name.upper())
            m.protoVer = PROTOCOL_VERSION
            for arg in args:
                m.arguments.append(str(arg))
            m.testnet = self.multiplexer.testnet
            m.signature = self.signing_key.sign(m.SerializeToString())[:64]
            data = m.SerializeToString()

            relay_addr = None
            if node.nat_type == SYMMETRIC or \
                    (node.nat_type == RESTRICTED and self.sourceNode.nat_type == SYMMETRIC):
                relay_addr = node.relay_node

            d = defer.Deferred()
            if m.command != HOLE_PUNCH:
                timeout = reactor.callLater(self._waitTimeout, self.timeout, node)
                self._outstanding[msgID] = [d, address, timeout]
                self.log.debug("calling remote function %s on %s (msgid %s)" % (name, address, b64encode(msgID)))

            self.multiplexer.send_message(data, address, relay_addr)

            if self.multiplexer[address].state != State.CONNECTED and \
                            node.nat_type == RESTRICTED and \
                            self.sourceNode.nat_type != SYMMETRIC and \
                            node.relay_node is not None:
                self.hole_punch(Node(digest("null"), node.relay_node[0], node.relay_node[1], nat_type=FULL_CONE),
                                address[0], address[1], "True")
                self.log.debug("sending hole punch message to %s" % address[0] + ":" + str(address[1]))

            return d

        return func
