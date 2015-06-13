import random

from twisted.internet import defer

from dht.rpcudp import RPCProtocol
from dht.node import Node
from dht.routing import RoutingTable
from dht.log import Logger
from dht.utils import digest
from dht import kprotocol


class KademliaProtocol(RPCProtocol):
    def __init__(self, sourceNode, storage, ksize):
        RPCProtocol.__init__(self)
        self.router = RoutingTable(self, ksize, sourceNode)
        self.storage = storage
        self.sourceNode = sourceNode
        self.log = Logger(system=self)

    def getRefreshIDs(self):
        """
        Get ids to search for to keep old buckets up to date.
        """
        ids = []
        for bucket in self.router.getLonelyBuckets():
            ids.append(random.randint(*bucket.range))
        return ids

    def rpc_stun(self, sender):
        node = kprotocol.Node()
        node.guid = sender.id
        node.ip = sender.ip
        node.port = sender.port
        return [node.SerializeToString()]

    def rpc_ping(self, sender):
        self.router.addContact(sender)
        return [self.sourceNode.id]

    def rpc_store(self, sender, keyword, key, value):
        self.router.addContact(sender)
        self.log.debug("got a store request from %s, storing value" % str(sender))
        self.storage[keyword] = (key, value)
        return ["True"]

    def rpc_find_node(self, sender, key):
        self.log.info("finding neighbors of %i in local table" % long(key.encode('hex'), 16))
        self.router.addContact(sender)
        node = Node(key)
        nodeList = map(tuple, self.router.findNeighbors(node, exclude=sender))
        ret = []
        for n in nodeList:
            node = kprotocol.Node()
            node.guid = n[0]
            node.ip = n[1]
            node.port = n[2]
            ret.append(node.SerializeToString())
        return ret

    def rpc_find_value(self, sender, key):
        self.router.addContact(sender)
        ret = []
        ret.append("value")
        value = self.storage.get(key, None)
        if value is None:
            return self.rpc_find_node(sender, key)
        ret.extend(value)
        return ret

    def callFindNode(self, nodeToAsk, nodeToFind):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.find_node(address, nodeToFind.id)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callFindValue(self, nodeToAsk, nodeToFind):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.find_value(address, nodeToFind.id)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callPing(self, nodeToAsk):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.ping(address)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callStore(self, nodeToAsk, keyword, key, value):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.store(address, keyword, key, value)
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
        ds = []
        for keyword in self.storage.iterkeys():
            keynode = Node(keyword)
            neighbors = self.router.findNeighbors(keynode)
            if len(neighbors) > 0:
                newNodeClose = node.distanceTo(keynode) < neighbors[-1].distanceTo(keynode)
                thisNodeClosest = self.sourceNode.distanceTo(keynode) < neighbors[0].distanceTo(keynode)
            if len(neighbors) == 0 or (newNodeClose and thisNodeClosest):
                for k, v in self.storage.iteritems(keyword):
                    ds.append(self.callStore(node, keyword, k, v))
        return defer.gatherResults(ds)

    def handleCallResponse(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if result[0]:
            self.log.info("got response from %s, adding to router" % node)
            self.router.addContact(node)
            if self.router.isNewNode(node):
                self.transferKeyValues(node)
        else:
            self.log.debug("no response from %s, removing from router" % node)
            self.router.removeContact(node)
        return result
