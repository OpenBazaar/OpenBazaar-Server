import random
import pyelliptic
import bitcoin

from twisted.internet import defer

from binascii import hexlify

from dht.rpcudp import RPCProtocol
from dht.node import Node
from dht.routing import RoutingTable
from dht.log import Logger
from dht import kprotocol


class KademliaProtocol(RPCProtocol):
    def __init__(self, sourceNode, storage, ksize):
        RPCProtocol.__init__(self)
        self.ksize = ksize
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
        self.addToRouter(sender)
        node = kprotocol.Node()
        node.guid = sender.id
        node.ip = sender.ip
        node.port = sender.port
        return [node.SerializeToString()]

    def rpc_ping(self, sender):
        self.addToRouter(sender)
        return [self.sourceNode.id]

    def rpc_store(self, sender, keyword, key, value):
        self.addToRouter(sender)
        self.log.debug("got a store request from %s, storing value" % str(sender))
        self.storage[keyword] = (key, value)
        return ["True"]

    def rpc_delete(self, sender, keyword, key, signature):
        self.addToRouter(sender)
        value = self.storage.getSpecific(keyword, key)
        if value is not None:
            try:
                node = kprotocol.Node()
                node.ParseFromString(value)
                pub = bitcoin.decode_pubkey(hexlify(node.publicKey), formt='hex_compressed')
                pubkey_hex = bitcoin.encode_pubkey(pub, formt="hex")
                pubkey_raw = bitcoin.changebase(pubkey_hex[2:],16,256,minlen=64)
                pubkey = '\x02\xca\x00 '+pubkey_raw[:32]+'\x00 '+pubkey_raw[32:]
                if pyelliptic.ECC(pubkey=pubkey).verify(signature, key):
                    self.storage.delete(keyword, key)
                    return ["True"]
            except:
                pass
        return ["False"]

    def rpc_find_node(self, sender, key):
        self.log.info("finding neighbors of %i in local table" % long(key.encode('hex'), 16))
        self.addToRouter(sender)
        node = Node(key)
        nodeList = self.router.findNeighbors(node, exclude=sender)
        ret = []
        print nodeList
        for n in nodeList:
            print n
            ret.append(n.proto.SerializeToString())
        return ret

    def rpc_find_value(self, sender, key):
        self.addToRouter(sender)
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

    def callDelete(self, nodeToAsk, keyword, key, signature):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.delete(address, keyword, key, signature)
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
            neighbors = self.router.findNeighbors(keynode, exclude=node)
            if len(neighbors) > 0:
                newNodeClose = node.distanceTo(keynode) < neighbors[-1].distanceTo(keynode)
                thisNodeClosest = self.sourceNode.distanceTo(keynode) < neighbors[0].distanceTo(keynode)
            if len(neighbors) == 0 \
                    or (newNodeClose and thisNodeClosest) \
                    or (thisNodeClosest and len(neighbors) < self.ksize):
                for k, v in self.storage.iteritems(keyword):
                    ds.append(self.callStore(node, keyword, k, v))
        return defer.gatherResults(ds)

    def handleCallResponse(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if result[0]:
            if self.router.isNewNode(node):
                self.transferKeyValues(node)
            self.log.info("got response from %s, adding to router" % node)
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
        if self.router.isNewNode(node):
            self.log.debug("Found a new node, transferring key/values")
            self.transferKeyValues(node)
        self.router.addContact(node)

