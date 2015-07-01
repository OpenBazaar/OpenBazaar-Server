__author__ = 'chris'

import random
from hashlib import sha1
from base64 import b64encode

from twisted.internet import reactor
from twisted.internet import defer

from dht.log import Logger
from dht.kprotocol import Message, Command
from dht import node

from txrudp.rudp import ConnectionMultiplexer
from txrudp.connection import HandlerFactory, Handler, ConnectionFactory

class RPCProtocol(ConnectionMultiplexer):

    def __init__(self, ip_address, waitTimeout=5, noisy=True):
        """
        @param waitTimeout: Consider it a connetion failure if no response
        within this time window.
        """
        self._waitTimeout = waitTimeout
        self._outstanding = {}
        self.factory = self.RPCHandlerFactory(noisy, waitTimeout, self._outstanding, self)
        ConnectionMultiplexer.__init__(self, ConnectionFactory(self.factory), ip_address)

    class RPCHandler(Handler):

        def __init__(self, noisy, waitTimeout, outstanding, instance):
            self.connection = None
            self.log = Logger(system=self)
            self.noisy = noisy
            self._waitTimeout = waitTimeout
            self._outstanding = outstanding
            self.instance = instance

        def receive_message(self, datagram):
            datagram = datagram.encode('latin-1')
            if len(datagram) < 22:
                self.log.msg("received datagram too small from %s, ignoring" % repr(self.connection.dest_addr))
                return False

            m = Message()
            try:
                m.ParseFromString(datagram)
                if m.sender.merchant:
                    sender = node.Node(m.sender.guid, self.connection.dest_addr[0], self.connection.dest_addr[1],
                                       pubkey=m.sender.publicKey, merchant=True, serverPort=m.sender.serverPort,
                                       transport=m.sender.transport)
                else:
                    sender = node.Node(m.sender.guid, self.connection.dest_addr[0], self.connection.dest_addr[1],
                                       pubkey=m.sender.publicKey)
            except:
                # If message isn't formatted property then ignore
                self.log.msg("Received unknown message from %s, ignoring" % repr(self.connection.dest_addr))
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
            f = getattr(self.instance, "rpc_%s" % funcname, None)
            if f is None or not callable(f):
                msgargs = (self.instance.__class__.__name__, funcname)
                self.log.error("%s has no callable method rpc_%s; ignoring request" % msgargs)
                return False
            d = defer.maybeDeferred(f, sender, *args)
            d.addCallback(self._sendResponse, funcname, msgID, sender)

        def _sendResponse(self, response, funcname, msgID, sender):
            if self.noisy:
                self.log.msg("sending response for msg id %s to %s" % (b64encode(msgID), sender))

            m = Message()
            m.messageID = msgID
            m.sender.MergeFrom(self.instance.sourceNode.proto)
            m.command = Command.Value(funcname.upper())
            for arg in response:
                m.arguments.append(arg)
            data = m.SerializeToString().decode('latin-1')
            self.connection.send_message(data)

        def handle_shutdown(self):
            print "Connection terminated"

    class RPCHandlerFactory(HandlerFactory):

        def __init__(self, noisy, waitTimeout, outstanding, instance):
            self.noisy = noisy
            self._waitTimeout = waitTimeout
            self._outstanding = outstanding
            self.instance = instance

        def make_new_handler(self, *args, **kwargs):
            return RPCProtocol.RPCHandler(self.noisy, self._waitTimeout, self._outstanding, self.instance)

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
            if self.noisy:
                self.log.msg("calling remote function %s on %s (msgid %s)" % (name, address, b64encode(msgID)))
            if address not in self:
                con = self.make_new_connection((self.sourceNode.ip, self.sourceNode.port), address)
            else:
                con = self[address]
            con.send_message(data.decode('latin-1'))
            d = defer.Deferred()
            timeout = reactor.callLater(self._waitTimeout, self._timeout, msgID)
            self._outstanding[msgID] = (d, timeout)
            return d
        return func