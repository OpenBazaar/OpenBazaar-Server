__author__ = 'chris'

import random
from hashlib import sha1
from base64 import b64encode

from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet import defer

from dht.log import Logger
from dht.kprotocol import Message, Command
from dht import node

class MalformedMessage(Exception):
    """
    Message does not contain what is expected.
    """


class RPCProtocol(protocol.DatagramProtocol):

    def __init__(self, waitTimeout=5, noisy=True):
        """
        @param waitTimeout: Consider it a connetion failure if no response
        within this time window.
        """
        self.noisy = noisy
        self.log = Logger(system=self)
        self._waitTimeout = waitTimeout
        self._outstanding = {}

    def datagramReceived(self, datagram, address):
        if len(datagram) < 22:
            self.log.msg("received datagram too small from %s, ignoring" % repr(address))
            return False

        m = Message()
        try:
            m.ParseFromString(datagram)
            if m.sender.merchant:
                sender = node.Node(m.sender.guid, address[0], address[1], pubkey=m.sender.publicKey,
                                   merchant=True, serverPort=m.sender.serverPort, transport=m.sender.transport)
            else:
                sender = node.Node(m.sender.guid, address[0], address[1], pubkey=m.sender.publicKey)
        except:
            # If message isn't formatted property then ignore
            self.log.msg("Received unknown message from %s, ignoring" % repr(address))
            return False

        msgID = m.messageID
        data = tuple(m.arguments)
        if msgID in self._outstanding:
            self._acceptResponse(msgID, data, sender)
        else:
            self._acceptRequest(msgID, str(Command.Name(m.command)).lower(), data, sender)

    def _acceptResponse(self, msgID, data, sender):
        msgargs = (b64encode(msgID), sender)
        if self.noisy:
            self.log.msg("Received response for message id %s from %s" % msgargs)
        d, timeout = self._outstanding[msgID]
        timeout.cancel()
        d.callback((True, data))
        del self._outstanding[msgID]

    def _acceptRequest(self, msgID, funcname, args, sender):
        if self.noisy:
            self.log.msg("received request from %s, command %s" % (sender, funcname.upper()))
        f = getattr(self, "rpc_%s" % funcname, None)
        if f is None or not callable(f):
            msgargs = (self.__class__.__name__, funcname)
            self.log.error("%s has no callable method rpc_%s; ignoring request" % msgargs)
            return False
        d = defer.maybeDeferred(f, sender, *args)
        d.addCallback(self._sendResponse, funcname, msgID, sender)

    def _sendResponse(self, response, funcname, msgID, sender):
        if self.noisy:
            self.log.msg("sending response for msg id %s to %s" % (b64encode(msgID), sender))

        m = Message()
        m.messageID = msgID
        m.sender.MergeFrom(self.sourceNode.proto)
        m.command = Command.Value(funcname.upper())
        for arg in response:
            m.arguments.append(arg)
        data = m.SerializeToString()
        self.transport.write(data, (sender.ip, sender.port))

    def _timeout(self, msgID):
        args = (b64encode(msgID), self._waitTimeout)
        self.log.error("Did not received reply for msg id %s within %i seconds" % args)
        self._outstanding[msgID][0].callback((False, None))
        del self._outstanding[msgID]

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
            m.sender.MergeFrom(self.sourceNode.proto)
            m.command = Command.Value(name.upper())
            for arg in args:
                m.arguments.append(arg)
            data = m.SerializeToString()
            if len(data) > 8192:  # This check can be removed when we switch to rUDP
                msg = "Total length of function name and arguments cannot exceed 8K"
                raise MalformedMessage(msg)
            if self.noisy:
                self.log.msg("calling remote function %s on %s (msgid %s)" % (name, address, b64encode(msgID)))
            self.transport.write(data, address)
            d = defer.Deferred()
            timeout = reactor.callLater(self._waitTimeout, self._timeout, msgID)
            self._outstanding[msgID] = (d, timeout)
            return d
        return func