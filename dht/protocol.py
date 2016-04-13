"""
Copyright (c) 2014 Brian Muller
Copyright (c) 2015 OpenBazaar
"""

import random
from twisted.internet import reactor
from zope.interface import implements
import nacl.signing

from dht.node import Node
from dht.routing import RoutingTable
from dht.utils import digest
from log import Logger
from net.rpcudp import RPCProtocol
from interfaces import MessageProcessor
from protos import objects
from protos.message import PING, STUN, STORE, DELETE, FIND_NODE, FIND_VALUE, HOLE_PUNCH, INV, VALUES


class KademliaProtocol(RPCProtocol):
    implements(MessageProcessor)

    def __init__(self, sourceNode, storage, ksize, database, signing_key):
        self.ksize = ksize
        self.router = RoutingTable(self, ksize, sourceNode)
        self.storage = storage
        self.sourceNode = sourceNode
        self.multiplexer = None
        self.db = database
        self.signing_key = signing_key
        self.log = Logger(system=self)
        self.handled_commands = [PING, STUN, STORE, DELETE, FIND_NODE, FIND_VALUE, HOLE_PUNCH, INV, VALUES]
        self.recent_transfers = set()
        RPCProtocol.__init__(self, sourceNode, self.router)

    def connect_multiplexer(self, multiplexer):
        self.multiplexer = multiplexer

    def getRefreshIDs(self):
        """
        Get ids to search for to keep old buckets up to date.
        """
        ids = []
        for bucket in self.router.getLonelyBuckets():
            ids.append(random.randint(*bucket.range))
        return ids

    def rpc_stun(self, sender):
        self.addToRouter(sender)
        return [sender.ip, str(sender.port)]

    def rpc_ping(self, sender):
        self.addToRouter(sender)
        return [self.sourceNode.getProto().SerializeToString()]

    def rpc_store(self, sender, keyword, key, value, ttl):
        self.addToRouter(sender)
        self.log.debug("got a store request from %s, storing value" % str(sender))
        if len(keyword) == 20 and len(key) <= 33 and len(value) <= 2100 and int(ttl) <= 604800:
            self.storage[keyword] = (key, value, int(ttl))
            return ["True"]
        else:
            return ["False"]

    def rpc_delete(self, sender, keyword, key, signature):
        self.addToRouter(sender)
        value = self.storage.getSpecific(keyword, key)
        if value is not None:
            # Try to delete a message from the dht
            if keyword == digest(sender.id):
                try:
                    verify_key = nacl.signing.VerifyKey(sender.pubkey)
                    verify_key.verify(key, signature)
                    self.storage.delete(keyword, key)
                    return ["True"]
                except Exception:
                    return ["False"]
            # Or try to delete a pointer
            else:
                try:
                    node = objects.Node()
                    node.ParseFromString(value)
                    pubkey = node.publicKey
                    try:
                        verify_key = nacl.signing.VerifyKey(pubkey)
                        verify_key.verify(key, signature)
                        self.storage.delete(keyword, key)
                        return ["True"]
                    except Exception:
                        return ["False"]
                except Exception:
                    pass
        return ["False"]

    def rpc_find_node(self, sender, key):
        self.log.debug("finding neighbors of %s in local table" % key.encode('hex'))
        self.addToRouter(sender)
        node = Node(key)
        nodeList = self.router.findNeighbors(node, exclude=sender)
        ret = []
        if self.sourceNode.id == key:
            ret.append(self.sourceNode.getProto().SerializeToString())
        for n in nodeList:
            ret.append(n.getProto().SerializeToString())
        return ret

    def rpc_find_value(self, sender, keyword):
        self.addToRouter(sender)
        ret = ["value"]
        value = self.storage.get(keyword, None)
        if value is None:
            return self.rpc_find_node(sender, keyword)
        ret.extend(value)
        return ret

    def rpc_inv(self, sender, *serlialized_invs):
        self.addToRouter(sender)
        ret = []
        for inv in serlialized_invs:
            try:
                i = objects.Inv()
                i.ParseFromString(inv)
                if self.storage.getSpecific(i.keyword, i.valueKey) is None:
                    ret.append(inv)
            except Exception:
                pass
        return ret

    def rpc_values(self, sender, *serialized_values):
        self.addToRouter(sender)
        for val in serialized_values[:100]:
            try:
                v = objects.Value()
                v.ParseFromString(val)
                self.storage[v.keyword] = (v.valueKey, v.serializedData, int(v.ttl))
            except Exception:
                pass
        return ["True"]

    def callFindNode(self, nodeToAsk, nodeToFind):
        d = self.find_node(nodeToAsk, nodeToFind.id)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callFindValue(self, nodeToAsk, nodeToFind):
        d = self.find_value(nodeToAsk, nodeToFind.id)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callPing(self, nodeToAsk):
        d = self.ping(nodeToAsk)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callStore(self, nodeToAsk, keyword, key, value, ttl):
        d = self.store(nodeToAsk, keyword, key, value, str(int(round(ttl))))
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callDelete(self, nodeToAsk, keyword, key, signature):
        d = self.delete(nodeToAsk, keyword, key, signature)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callInv(self, nodeToAsk, serlialized_inv_list):
        d = self.inv(nodeToAsk, *serlialized_inv_list)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callValues(self, nodeToAsk, serlialized_values_list):
        d = self.values(nodeToAsk, *serlialized_values_list)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def transferKeyValues(self, node):
        """
        Given a new node, send it all the keys/values it should be storing.

        @param node: A new node that just joined (or that we just found out
        about).

        Process:
        For each key in storage, get k closest nodes.  If newnode is closer
        than the furtherst in that list, and the node for this server
        is closer than the closest in that list, then store the key/value
        on the new node (per section 2.5 of the paper)
        """
        def send_values(inv_list):
            values = []
            if inv_list[0]:
                for requested_inv in inv_list[1]:
                    try:
                        i = objects.Inv()
                        i.ParseFromString(requested_inv)
                        value = self.storage.getSpecific(i.keyword, i.valueKey)
                        if value is not None:
                            v = objects.Value()
                            v.keyword = i.keyword
                            v.valueKey = i.valueKey
                            v.serializedData = value
                            v.ttl = int(round(self.storage.get_ttl(i.keyword, i.valueKey)))
                            values.append(v.SerializeToString())
                    except Exception:
                        pass
                if len(values) > 0:
                    self.callValues(node, values)

        inv = []
        for keyword in self.storage.iterkeys():
            keyword = keyword[0].decode("hex")
            keynode = Node(keyword)
            neighbors = self.router.findNeighbors(keynode, exclude=node)
            if len(neighbors) > 0:
                newNodeClose = node.distanceTo(keynode) < neighbors[-1].distanceTo(keynode)
                thisNodeClosest = self.sourceNode.distanceTo(keynode) < neighbors[0].distanceTo(keynode)
            if len(neighbors) == 0 \
                    or (newNodeClose and thisNodeClosest) \
                    or (thisNodeClosest and len(neighbors) < self.ksize):
                # pylint: disable=W0612
                for k, v in self.storage.iteritems(keyword):
                    i = objects.Inv()
                    i.keyword = keyword
                    i.valueKey = k
                    inv.append(i.SerializeToString())
        if len(inv) > 100:
            random.shuffle(inv)
        if len(inv) > 0:
            self.callInv(node, inv[:100]).addCallback(send_values)

    def handleCallResponse(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if result[0]:
            if self.isNewConnection(node) and node.id not in self.recent_transfers:
                if len(self.recent_transfers) == 10:
                    self.recent_transfers.pop()
                self.recent_transfers.add(node.id)
                self.log.debug("call response from new node, transferring key/values")
                reactor.callLater(1, self.transferKeyValues, node)
            self.router.addContact(node)
        else:
            self.log.debug("no response from %s, removing from router" % node)
            self.router.removeContact(node)
        return result

    def addToRouter(self, node):
        """
        Called by rpc_ functions when a node sends them a request.
        We add the node to our router and transfer our stored values
        if they are new and within our neighborhood.
        """
        if self.isNewConnection(node) and node.id not in self.recent_transfers:
            if len(self.recent_transfers) == 10:
                self.recent_transfers.pop()
            self.recent_transfers.add(node.id)
            self.log.debug("found a new node, transferring key/values")
            reactor.callLater(1, self.transferKeyValues, node)
        self.router.addContact(node)

    def isNewConnection(self, node):
        if (node.ip, node.port) in self.multiplexer:
            return self.multiplexer[(node.ip, node.port)].handler.check_new_connection()
        else:
            return False

    def __iter__(self):
        return iter(self.handled_commands)

