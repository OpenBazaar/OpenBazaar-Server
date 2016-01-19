"""
Copyright (c) 2014 Brian Muller
Copyright (c) 2015 OpenBazaar
"""

from collections import Counter, defaultdict
from twisted.internet import defer

from log import Logger

from dht.utils import deferredDict
from dht.node import Node, NodeHeap

from protos import objects


class SpiderCrawl(object):
    """
    Crawl the network and look for given 160-bit keys.
    """

    def __init__(self, protocol, node, peers, ksize, alpha):
        """
        Create a new C{SpiderCrawl}er.

        Args:
            protocol: A :class:`~kademlia.protocol.KademliaProtocol` instance.
            node: A :class:`~kademlia.node.Node` representing the key we're looking for
            peers: A list of :class:`~kademlia.node.Node` instances that provide the entry point for the network
            ksize: The value for k based on the paper
            alpha: The value for alpha based on the paper
        """
        self.protocol = protocol
        self.ksize = ksize
        self.alpha = alpha
        self.node = node
        self.nearest = NodeHeap(self.node, self.ksize)
        self.lastIDsCrawled = []
        self.log = Logger(system=self)
        self.log.debug("creating spider with peers: %s" % peers)
        self.nearest.push(peers)

    def _find(self, rpcmethod):
        """
        Get either a value or list of nodes.

        Args:
            rpcmethod: The protocol's callFindValue or callFindNode.

        The process:
          1. calls find_* to current ALPHA nearest not already queried nodes,
             adding results to current nearest list of k nodes.
          2. current nearest list needs to keep track of who has been queried already
             sort by nearest, keep KSIZE
          3. if list is same as last time, next call should be to everyone not
             yet queried
          4. repeat, unless nearest list has all been queried, then ur done
        """
        self.log.debug("crawling with nearest: %s" % str(tuple(self.nearest)))
        count = self.alpha
        if self.nearest.getIDs() == self.lastIDsCrawled:
            self.log.debug("last iteration same as current - checking all in list now")
            count = len(self.nearest)
        self.lastIDsCrawled = self.nearest.getIDs()

        ds = {}
        for peer in self.nearest.getUncontacted()[:count]:
            ds[peer.id] = rpcmethod(peer, self.node)
            self.nearest.markContacted(peer)
        return deferredDict(ds).addCallback(self._nodesFound)


class ValueSpiderCrawl(SpiderCrawl):
    def __init__(self, protocol, node, peers, ksize, alpha):
        SpiderCrawl.__init__(self, protocol, node, peers, ksize, alpha)
        # keep track of the single nearest node without value - per
        # section 2.3 so we can set the key there if found
        self.nearestWithoutValue = NodeHeap(self.node, 1)

    def find(self):
        """
        Find either the closest nodes or the value requested.
        """
        return self._find(self.protocol.callFindValue)

    def _nodesFound(self, responses):
        """
        Handle the result of an iteration in _find.
        """
        toremove = []
        foundValues = []
        for peerid, response in responses.items():
            response = RPCFindResponse(response)
            if not response.happened():
                toremove.append(peerid)
            elif response.hasValue():
                # since we get back a list of values, we will just extend foundValues (excluding duplicates)
                foundValues = list(set(foundValues) | set(response.getValue()))
            else:
                peer = self.nearest.getNodeById(peerid)
                self.nearestWithoutValue.push(peer)
                self.nearest.push(response.getNodeList())
        self.nearest.remove(toremove)

        if len(foundValues) > 0:
            return self._handleFoundValues(foundValues)
        if self.nearest.allBeenContacted():
            # not found!
            return None
        return self.find()

    def _handleFoundValues(self, values):
        """
        We got some values!  Exciting.  But let's make sure
        they're all the same or freak out a little bit.  Also,
        make sure we tell the nearest node that *didn't* have
        the value to store it.
        """

        value_dict = defaultdict(list)
        ttl_dict = defaultdict(list)
        for v in values:
            try:
                d = objects.Value()
                d.ParseFromString(v)
                value_dict[d.valueKey].append(d.serializedData)
                ttl_dict[d.valueKey].append(d.ttl)
            except Exception:
                pass
        value = []
        for k, v in value_dict.items():
            ttl = ttl_dict[k]
            if len(v) > 1:
                valueCounts = Counter(v)
                v = [valueCounts.most_common(1)[0][0]]
                ttlCounts = Counter(ttl_dict[k])
                ttl = [ttlCounts.most_common(1)[0][0]]
            val = objects.Value()
            val.valueKey = k
            val.serializedData = v[0]
            val.ttl = ttl[0]
            value.append(val.SerializeToString())

        ds = []
        peerToSaveTo = self.nearestWithoutValue.popleft()
        if peerToSaveTo is not None:
            for v in value:
                try:
                    val = objects.Value()
                    val.ParseFromString(v)
                    ds.append(self.protocol.callStore(peerToSaveTo, self.node.id, val.valueKey,
                                                      val.serializedData, val.ttl))
                except Exception:
                    pass
            return defer.gatherResults(ds).addCallback(lambda _: value)
        return value


class NodeSpiderCrawl(SpiderCrawl):
    def find(self):
        """
        Find the closest nodes.
        """
        return self._find(self.protocol.callFindNode)

    def _nodesFound(self, responses):
        """
        Handle the result of an iteration in _find.
        """
        toremove = []
        for peerid, response in responses.items():
            response = RPCFindResponse(response)
            if not response.happened():
                toremove.append(peerid)
            else:
                self.nearest.push(response.getNodeList())
        self.nearest.remove(toremove)

        if self.nearest.allBeenContacted():
            return list(self.nearest)
        return self.find()


class RPCFindResponse(object):
    def __init__(self, response):
        """
        A wrapper for the result of a RPC find.

        Args:
            response: This will be a tuple of (<response received>, <value>)
                      where <value> will be a list of tuples if not found or
                      a dictionary of {'value': v} where v is the value desired
        """
        self.response = response

    def happened(self):
        """
        Did the other host actually respond?
        """
        return self.response[0]

    def hasValue(self):
        if len(self.response) > 0 and len(self.response[1]) > 0:
            if self.response[1][0] == "value":
                return True
        return False

    def getValue(self):
        return self.response[1][1:]

    def getNodeList(self):
        """
        Get the node list in the response.  If there's no value, this should
        be set.
        """
        nodes = []
        for node in self.response[1]:
            try:
                n = objects.Node()
                n.ParseFromString(node)
                newNode = Node(n.guid, n.nodeAddress.ip, n.nodeAddress.port, n.signedPublicKey,
                               None if not n.HasField("relayAddress") else (n.relayAddress.ip, n.relayAddress.port),
                               n.natType,
                               n.vendor)
                nodes.append(newNode)
            except Exception:
                pass
        return nodes
