"""
Package for interacting on the network at a high level.
"""
import random
import pickle

from twisted.internet.task import LoopingCall
from twisted.internet import defer, reactor, task

from dht.log import Logger
from dht.protocol import KademliaProtocol
from dht.utils import deferredDict, digest
from dht.storage import ForgetfulStorage
from dht.node import Node
from dht.crawling import ValueSpiderCrawl
from dht.crawling import NodeSpiderCrawl
from dht import kprotocol

class Server(object):
    """
    High level view of a node instance.  This is the object that should be created
    to start listening as an active node on the network.
    """

    def __init__(self, ksize=20, alpha=3, node=None, storage=None):
        """
        Create a server instance.  This will start listening on the given port.

        Args:
            ksize (int): The k parameter from the paper
            alpha (int): The alpha parameter from the paper
            id: The id for this node on the network.
            storage: An instance that implements :interface:`~kademlia.storage.IStorage`
        """
        self.ksize = ksize
        self.alpha = alpha
        self.log = Logger(system=self)
        self.storage = storage or ForgetfulStorage()
        self.node = node or Node(digest(random.getrandbits(255)))
        self.protocol = KademliaProtocol(self.node, self.storage, ksize)
        self.refreshLoop = LoopingCall(self.refreshTable).start(3600)

    def listen(self, port):
        """
        Start listening on the given port.

        This is the same as calling::

            reactor.listenUDP(port, server.protocol)
        """
        return reactor.listenUDP(port, self.protocol)

    def refreshTable(self):
        """
        Refresh buckets that haven't had any lookups in the last hour
        (per section 2.3 of the paper).
        """
        ds = []
        for id in self.protocol.getRefreshIDs():
            node = Node(id)
            nearest = self.protocol.router.findNeighbors(node, self.alpha)
            spider = NodeSpiderCrawl(self.protocol, node, nearest)
            ds.append(spider.find())

        def republishKeys(_):
            ds = []
            # Republish keys older than one hour
            for keyword in self.storage.iterkeys():
                for k, v in self.storage.iteritems(keyword):
                    if self.storage[keyword].get_ttl(k) < 601200:
                        ds.append(self.set(keyword, k, v))

        return defer.gatherResults(ds).addCallback(republishKeys)

    def bootstrappableNeighbors(self):
        """
        Get a :class:`list` of (ip, port) :class:`tuple` pairs suitable for use as an argument
        to the bootstrap method.

        The server should have been bootstrapped
        already - this is just a utility for getting some neighbors and then
        storing them if this server is going down for a while.  When it comes
        back up, the list of nodes can be used to bootstrap.
        """
        neighbors = self.protocol.router.findNeighbors(self.node)
        return [ tuple(n)[-2:] for n in neighbors ]

    def bootstrap(self, addrs):
        """
        Bootstrap the server by connecting to other known nodes in the network.

        Args:
            addrs: A `list` of (ip, port) `tuple` pairs.  Note that only IP addresses
                   are acceptable - hostnames will cause an error.
        """

        # if the transport hasn't been initialized yet, wait a second
        if self.protocol.transport is None:
            return task.deferLater(reactor, 1, self.bootstrap, addrs)

        def initTable(results):
            nodes = []
            for addr, result in results.items():
                if result[0]:
                    nodes.append(Node(result[1][0], addr[0], addr[1]))
            spider = NodeSpiderCrawl(self.protocol, self.node, nodes, self.ksize, self.alpha)
            return spider.find()

        ds = {}
        for addr in addrs:
            ds[addr] = self.protocol.ping(addr)
        return deferredDict(ds).addCallback(initTable)

    def inetVisibleIP(self):
        """
        Get the internet visible IP's of this node as other nodes see it.

        Returns:
            A `list` of IP's.  If no one can be contacted, then the `list` will be empty.
        """
        def handle(results):
            ips = []
            for result in results:
                if result[0]:
                    n = kprotocol.Node()
                    n.ParseFromString(result[1][0])
                    ips.append((n.ip, n.port))
            self.log.debug("other nodes think our ip is %s" % str(ips))
            return ips

        ds = []
        for neighbor in self.bootstrappableNeighbors():
            ds.append(self.protocol.stun(neighbor))
        return defer.gatherResults(ds).addCallback(handle)

    def get(self, keyword):
        """
        Get a key if the network has it.

        Returns:
            :class:`None` if not found, the value otherwise.
        """
        node = Node(digest(keyword))
        nearest = self.protocol.router.findNeighbors(node)
        if len(nearest) == 0:
            self.log.warning("There are no known neighbors to get key %s" % keyword)
            return defer.succeed(None)
        spider = ValueSpiderCrawl(self.protocol, node, nearest, self.ksize, self.alpha)
        return spider.find()

    def set(self, keyword, key, value):
        """
        Set the given key/value tuple at the hash of the given keyword.
        All values stored in the DHT are stored as dictionaries of key/value
        pairs. If a value already exists for a given keyword, the new key/value
        pair will be appended to the dictionary.

        Args:
            keyword: a `string` keyword. The SHA1 hash of which will be used as
                the key when inserting in the DHT.
            key: the 20 byte hash of the contract.
            value: a serialized `kprotocol.Node` object with all optional fields
                provided.

        Return: True if at least one peer responded. False if the store rpc
            completely failed.
        """
        self.log.debug("setting '%s' = '%s':'%s' on network" % (keyword, key, value))
        dkey = digest(keyword)

        def store(nodes):
            self.log.info("setting '%s' on %s" % (keyword, map(str, nodes)))
            ds = [self.protocol.callStore(node, dkey, key, value) for node in nodes]

            keynode = Node(keyword)
            ownBucket = self.protocol.router.buckets[self.protocol.router.getBucketFor(self.node)]
            if ownBucket.hasInRange(keynode):
                self.log.debug("got a store request from %s, storing value" % str(self.node))
                self.storage[keyword] = (key, value)

            return defer.DeferredList(ds).addCallback(self._anyRespondSuccess)

        node = Node(dkey)
        nearest = self.protocol.router.findNeighbors(node)
        if len(nearest) == 0:
            self.log.warning("There are no known neighbors to set key %s" % key)
            return defer.succeed(False)
        spider = NodeSpiderCrawl(self.protocol, node, nearest, self.ksize, self.alpha)
        return spider.find().addCallback(store)

    def _anyRespondSuccess(self, responses):
        """
        Given the result of a DeferredList of calls to peers, ensure that at least
        one of them was contacted and responded with a Truthy result.
        """
        for deferSuccess, result in responses:
            peerReached, peerResponse = result
            if deferSuccess and peerReached and peerResponse:
                return True
        return False

    def saveState(self, fname):
        """
        Save the state of this node (the alpha/ksize/id/immediate neighbors)
        to a cache file with the given fname.
        """
        data = { 'ksize': self.ksize,
                 'alpha': self.alpha,
                 'id': self.node.id,
                 'neighbors': self.bootstrappableNeighbors() }
        if len(data['neighbors']) == 0:
            self.log.warning("No known neighbors, so not writing to cache.")
            return
        with open(fname, 'w') as f:
            pickle.dump(data, f)

    @classmethod
    def loadState(self, fname):
        """
        Load the state of this node (the alpha/ksize/id/immediate neighbors)
        from a cache file with the given fname.
        """
        with open(fname, 'r') as f:
            data = pickle.load(f)
        s = Server(data['ksize'], data['alpha'], data['id'])
        if len(data['neighbors']) > 0:
            s.bootstrap(data['neighbors'])
        return s

    def saveStateRegularly(self, fname, frequency=600):
        """
        Save the state of node with a given regularity to the given
        filename.

        Args:
            fname: File name to save retularly to
            frequencey: Frequency in seconds that the state should be saved.
                        By default, 10 minutes.
        """
        loop = LoopingCall(self.saveState, fname)
        loop.start(frequency)
        return loop
