"""
Package for interacting on the network at a high level.

Copyright (c) 2014 Brian Muller
Copyright (c) 2015 OpenBazaar
"""

import pickle
import httplib
from binascii import hexlify
from twisted.internet.task import LoopingCall
from twisted.internet import defer, reactor, task

import nacl.signing
import nacl.hash
import nacl.encoding

from seed import peers
from log import Logger
from dht.protocol import KademliaProtocol
from dht.utils import deferredDict, digest
from dht.storage import ForgetfulStorage
from dht.node import Node
from dht.crawling import ValueSpiderCrawl
from dht.crawling import NodeSpiderCrawl

from protos import objects

from constants import SEED


def _anyRespondSuccess(responses):
    """
    Given the result of a DeferredList of calls to peers, ensure that at least
    one of them was contacted and responded with a Truthy result.
    """
    for deferSuccess, result in responses:
        peerReached, peerResponse = result
        if deferSuccess and peerReached and peerResponse:
            return True
    return False


class Server(object):
    """
    High level view of a node instance.  This is the object that should be created
    to start listening as an active node on the network.
    """

    def __init__(self, node, db, ksize=20, alpha=3, storage=None):
        """
        Create a server instance.  This will start listening on the given port.

        Args:
            node: The node instance for this peer. It must contain (at minimum) an ID,
                public key, ip address, and port.
            ksize (int): The k parameter from the paper
            alpha (int): The alpha parameter from the paper
            storage: An instance that implements :interface:`~dht.storage.IStorage`
        """
        self.ksize = ksize
        self.alpha = alpha
        self.log = Logger(system=self)
        self.storage = storage or ForgetfulStorage()
        self.node = node
        self.protocol = KademliaProtocol(self.node, self.storage, ksize, db)
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
        for rid in self.protocol.getRefreshIDs():
            node = Node(rid)
            nearest = self.protocol.router.findNeighbors(node, self.alpha)
            spider = NodeSpiderCrawl(self.protocol, node, nearest, self.ksize, self.alpha)
            ds.append(spider.find())

        def republishKeys(_):
            ds = []
            # Republish keys older than one hour
            for keyword in self.storage.iterkeys():
                for k, v in self.storage.iteritems(keyword):
                    ttl = self.storage.get_ttl(keyword, k)
                    if ttl < 601200:
                        ds.append(self.set(keyword, k, v, ttl))

        return defer.gatherResults(ds).addCallback(republishKeys)

    def querySeed(self, list_seed_pubkey):
        """
        Query an HTTP seed and return a `list` if (ip, port) `tuple` pairs.

        Args:
            Receives a list of one or more tuples Example [(seed, pubkey)]
            seed: A `string` consisting of "ip:port" or "hostname:port"
            pubkey: The hex encoded public key to verify the signature on the response
        """

        nodes = []
        if not list_seed_pubkey:
            self.log.error('failed to query seed {0} from ob.cfg'.format(list_seed_pubkey))
            return nodes
        else:
            for sp in list_seed_pubkey:
                seed, pubkey = sp
                try:
                    self.log.info("querying %s for peers" % seed)
                    # nodes = []
                    c = httplib.HTTPConnection(seed)
                    c.request("GET", "/")
                    response = c.getresponse()
                    self.log.debug("Http response from %s: %s, %s" % (seed, response.status, response.reason))
                    data = response.read()
                    reread_data = data.decode("zlib")
                    proto = peers.PeerSeeds()
                    proto.ParseFromString(reread_data)
                    for peer in proto.peer_data:
                        p = peers.PeerData()
                        p.ParseFromString(peer)
                        tup = (str(p.ip_address), p.port)
                        nodes.append(tup)
                    verify_key = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.HexEncoder)
                    verify_key.verify("".join(proto.peer_data), proto.signature)
                    self.log.info("%s returned %s addresses" % (seed, len(nodes)))
                    # return nodes
                except Exception, e:
                    self.log.error("failed to query seed: %s" % str(e))
            return nodes

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
        return [tuple(n)[-2:] for n in neighbors]

    def bootstrap(self, addrs):
        """
        Bootstrap the server by connecting to other known nodes in the network.

        Args:
            addrs: A `list` of (ip, port) `tuple` pairs.  Note that only IP addresses
                   are acceptable - hostnames will cause an error.
        """

        # if the transport hasn't been initialized yet, wait a second
        if self.protocol.multiplexer.transport is None:
            return task.deferLater(reactor, 1, self.bootstrap, addrs)
        self.log.info("bootstrapping with %s addresses, finding neighbors..." % len(addrs))

        def initTable(results):
            nodes = []
            for addr, result in results.items():
                if result[0]:
                    n = objects.Node()
                    try:
                        n.ParseFromString(result[1][0])
                        pubkey = n.signedPublicKey[len(n.signedPublicKey) - 32:]
                        verify_key = nacl.signing.VerifyKey(pubkey)
                        verify_key.verify(n.signedPublicKey)
                        h = nacl.hash.sha512(n.signedPublicKey)
                        hash_pow = h[64:128]
                        if int(hash_pow[:6], 16) >= 50 or hexlify(n.guid) != h[:40]:
                            raise Exception('Invalid GUID')
                        nodes.append(Node(n.guid, addr[0], addr[1], n.signedPublicKey))
                    except Exception:
                        self.log.warning("bootstrap node returned invalid GUID")
            spider = NodeSpiderCrawl(self.protocol, self.node, nodes, self.ksize, self.alpha)
            return spider.find()

        ds = {}
        for addr in addrs:
            if addr != (self.node.ip, self.node.port):
                ds[addr] = self.protocol.ping((addr[0], addr[1]))
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
                    ips.append((result[1][0], int(result[1][1])))
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
        dkey = digest(keyword)
        if self.storage.get(dkey) is not None:
            return defer.succeed(self.storage.get(dkey))
        node = Node(dkey)
        nearest = self.protocol.router.findNeighbors(node)
        if len(nearest) == 0:
            self.log.warning("there are no known neighbors to get key %s" % dkey.encode('hex'))
            return defer.succeed(None)
        spider = ValueSpiderCrawl(self.protocol, node, nearest, self.ksize, self.alpha)
        return spider.find()

    def set(self, keyword, key, value, ttl=604800):
        """
        Set the given key/value tuple at the hash of the given keyword.
        All values stored in the DHT are stored as dictionaries of key/value
        pairs. If a value already exists for a given keyword, the new key/value
        pair will be appended to the dictionary.

        Args:
            keyword: The keyword to use. Should be hashed with hash160 before
                passing it in here.
            key: the 20 byte hash of the data.
            value: a serialized `protos.objects.Node` object which serves as a
                pointer to the node storing the data.

        Return: True if at least one peer responded. False if the store rpc
            completely failed.
        """
        if len(keyword) != 20:
            return defer.succeed(False)

        self.log.debug("setting '%s' on network" % keyword.encode("hex"))

        def store(nodes):
            self.log.debug("setting '%s' on %s" % (keyword.encode("hex"), [str(i) for i in nodes]))
            ds = [self.protocol.callStore(node, keyword, key, value, ttl) for node in nodes]

            keynode = Node(keyword)
            if self.node.distanceTo(keynode) < max([n.distanceTo(keynode) for n in nodes]):
                self.storage[keyword] = (key, value, ttl)
                self.log.debug("got a store request from %s, storing value" % str(self.node))

            return defer.DeferredList(ds).addCallback(_anyRespondSuccess)

        node = Node(keyword)
        nearest = self.protocol.router.findNeighbors(node)
        if len(nearest) == 0:
            self.log.warning("there are no known neighbors to set keyword %s" % keyword.encode("hex"))
            return defer.succeed(False)
        spider = NodeSpiderCrawl(self.protocol, node, nearest, self.ksize, self.alpha)
        return spider.find().addCallback(store)

    def delete(self, keyword, key, signature):
        """
        Delete the given key/value pair from the keyword dictionary on the network.
        To delete you must provide a signature covering the key that you wish to
        delete. It will be verified against the public key stored in the value. We
        use our ksize as alpha to make sure we reach as many nodes storing our value
        as possible.

        Args:
            keyword: the `string` keyword where the data being deleted is stored.
            key: the 20 byte hash of the data.
            signature: a signature covering the key.

        """
        self.log.debug("deleting '%s':'%s' from the network" % (keyword.encode("hex"), key.encode("hex")))
        dkey = digest(keyword)

        def delete(nodes):
            self.log.debug("deleting '%s' on %s" % (key.encode("hex"), [str(i) for i in nodes]))
            ds = [self.protocol.callDelete(node, dkey, key, signature) for node in nodes]

            if self.storage.getSpecific(dkey, key) is not None:
                self.storage.delete(dkey, key)

            return defer.DeferredList(ds).addCallback(_anyRespondSuccess)

        node = Node(dkey)
        nearest = self.protocol.router.findNeighbors(node)
        if len(nearest) == 0:
            self.log.warning("there are no known neighbors to delete key %s" % key.encode("hex"))
            return defer.succeed(False)
        spider = NodeSpiderCrawl(self.protocol, node, nearest, self.ksize, self.ksize)
        return spider.find().addCallback(delete)

    def resolve(self, guid):
        """
        Given a guid return a `Node` object containing its ip and port or none if it's
        not found.

        Args:
            guid: the 20 raw bytes representing the guid.
        """
        node_to_find = Node(guid)

        def check_for_node(nodes):
            for node in nodes:
                if node.id == node_to_find.id:
                    return node
            return None
        index = self.protocol.router.getBucketFor(node_to_find)
        nodes = self.protocol.router.buckets[index].getNodes()
        for node in nodes:
            if node.id == node_to_find.id:
                return defer.succeed(node)
        nearest = self.protocol.router.findNeighbors(node_to_find)
        if len(nearest) == 0:
            self.log.warning("there are no known neighbors to find node %s" % node_to_find.id.encode("hex"))
            return defer.succeed(None)
        spider = NodeSpiderCrawl(self.protocol, node_to_find, nearest, self.ksize, self.alpha)
        return spider.find().addCallback(check_for_node)

    def saveState(self, fname):
        """
        Save the state of this node (the alpha/ksize/id/immediate neighbors)
        to a cache file with the given fname.
        """
        data = {'ksize': self.ksize,
                'alpha': self.alpha,
                'id': self.node.id,
                'vendor': self.node.vendor,
                'signed_pubkey': self.node.signed_pubkey,
                'neighbors': self.bootstrappableNeighbors(),
                'testnet': self.protocol.multiplexer.testnet}
        if len(data['neighbors']) == 0:
            self.log.warning("no known neighbors, so not writing to cache.")
            return
        with open(fname, 'w') as f:
            pickle.dump(data, f)

    @classmethod
    def loadState(cls, fname, ip_address, port, multiplexer, db, callback=None, storage=None):
        """
        Load the state of this node (the alpha/ksize/id/immediate neighbors)
        from a cache file with the given fname.
        """
        with open(fname, 'r') as f:
            data = pickle.load(f)
        if data['testnet'] != multiplexer.testnet:
            raise Exception('Cache uses wrong network parameters')
        n = Node(data['id'], ip_address, port, data['signed_pubkey'], data['vendor'])
        s = Server(n, db, data['ksize'], data['alpha'], storage=storage)
        s.protocol.connect_multiplexer(multiplexer)
        if len(data['neighbors']) > 0:
            if callback is not None:
                s.bootstrap(data['neighbors']).addCallback(callback)
            else:
                s.bootstrap(data['neighbors'])
        else:
            if callback is not None:
                s.bootstrap(s.querySeed(SEED))\
                    .addCallback(callback)
            else:
                s.bootstrap(s.querySeed(SEED))
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
