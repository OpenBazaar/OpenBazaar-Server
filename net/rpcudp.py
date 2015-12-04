"""
Copyright (c) 2014 Brian Muller
Copyright (c) 2015 OpenBazaar
"""

import random
import abc
import nacl.signing
import nacl.encoding
import nacl.hash
from binascii import hexlify
from hashlib import sha1
from base64 import b64encode
from twisted.internet import defer, reactor
from log import Logger
from protos.message import Message, Command, NOT_FOUND
from dht import node
from constants import PROTOCOL_VERSION, SEED_NODE, SEED_NODE_TESTNET


class RPCProtocol:
    """
    This is an abstract class for processing and sending rpc messages.
    A class that implements the `MessageProcessor` interface probably should
    extend this as it does most of the work of keeping track of messages.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, sourceNode, router, waitTimeout=5):
        """
        Args:
            proto: A protobuf `Node` object containing info about this node.
            router: A `RoutingTable` object from dht.routing. Implies a `network.Server` object
                    must be started first.
            waitTimeout: Consider it a connetion failure if no response
                    within this time window.
            noisy: Whether or not to log the output for this class.
            testnet: The network parameters to use.

        """
        self.sourceNode = sourceNode
        self.router = router
        self._waitTimeout = waitTimeout
        self._outstanding = {}
        self.log = Logger(system=self)

    def receive_message(self, datagram, connection):
        m = Message()
        try:
            m.ParseFromString(datagram)
            sender = node.Node(m.sender.guid, m.sender.ip, m.sender.port, m.sender.signedPublicKey, m.sender.vendor)
        except Exception:
            # If message isn't formatted property then ignore
            self.log.warning("received unknown message from %s, ignoring" % str(connection.dest_addr))
            return False

        if m.testnet != self.multiplexer.testnet:
            self.log.warning("received message from %s with incorrect network parameters." %
                             str(connection.dest_addr))
            connection.shutdown()
            return False

        if m.protoVer < PROTOCOL_VERSION:
            self.log.warning("received message from %s with incompatible protocol version." %
                             str(connection.dest_addr))
            connection.shutdown()
            return False

        # Check that the GUID is valid. If not, ignore
        if self.router.isNewNode(sender):
            try:
                pubkey = m.sender.signedPublicKey[len(m.sender.signedPublicKey) - 32:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(m.sender.signedPublicKey)
                h = nacl.hash.sha512(m.sender.signedPublicKey)
                pow_hash = h[64:128]
                if int(pow_hash[:6], 16) >= 50 or hexlify(m.sender.guid) != h[:40]:
                    raise Exception('Invalid GUID')

            except Exception:
                self.log.warning("received message from sender with invalid GUID, ignoring")
                connection.shutdown()
                return False

        if m.sender.vendor:
            self.db.VendorStore().save_vendor(m.sender.guid.encode("hex"), m.sender.ip,
                                              m.sender.port, m.sender.signedPublicKey)

        msgID = m.messageID
        if m.command == NOT_FOUND:
            data = None
        else:
            data = tuple(m.arguments)
        if msgID in self._outstanding:
            self._acceptResponse(msgID, data, sender)
        elif m.command != NOT_FOUND:
            self._acceptRequest(msgID, str(Command.Name(m.command)).lower(), data, sender, connection)

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
        data = m.SerializeToString()
        connection.send_message(data)

    def timeout(self, address, node_to_remove):
        """
        This timeout is called by the txrudp connection handler. We will run through the
        outstanding messages and callback false on any waiting on this IP address.
        """
        if node_to_remove is not None:
            self.router.removeContact(node_to_remove)
        for msgID, val in self._outstanding.items():
            if address == val[1]:
                val[0].callback((False, None))
                del self._outstanding[msgID]

    def rpc_hole_punch(self, sender, ip, port, relay="False"):
        """
        A method for handling an incoming HOLE_PUNCH message. Relay the message
        to the correct node if it's not for us. Otherwise send a datagram to allow
        the other node to punch through our NAT.
        """
        if relay == "True":
            self.hole_punch((ip, int(port)), sender.ip, sender.port)
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

        def func(address, *args):
            msgID = sha1(str(random.getrandbits(255))).digest()
            m = Message()
            m.messageID = msgID
            m.sender.MergeFrom(self.sourceNode.getProto())
            m.command = Command.Value(name.upper())
            m.protoVer = PROTOCOL_VERSION
            for arg in args:
                m.arguments.append(str(arg))
            m.testnet = self.multiplexer.testnet
            data = m.SerializeToString()
            d = defer.Deferred()
            if name != "hole_punch":
                seed = SEED_NODE_TESTNET if self.multiplexer.testnet else SEED_NODE
                hole_punch = reactor.callLater(3, self.hole_punch, seed, address[0], address[1], "True")
                if address in self.multiplexer:
                    hole_punch.cancel()
                self._outstanding[msgID] = [d, address, hole_punch]
                self.log.debug("calling remote function %s on %s (msgid %s)" % (name, address, b64encode(msgID)))
            else:
                self.log.debug("sending hole punch message to %s" % args[0] + ":" + str(args[1]))
            self.multiplexer.send_message(data, address)
            return d

        return func
