__author__ = 'chris'
import bitcoin, binascii

from twisted.trial import unittest
from twisted.test import proto_helpers

from dht.crawling import RPCFindResponse, NodeSpiderCrawl, ValueSpiderCrawl
from dht.node import Node, NodeHeap
from dht.utils import digest
from dht.kprotocol import TCP
from dht.storage import ForgetfulStorage
from dht.protocol import KademliaProtocol
from dht import kprotocol

class ValueSpiderCrawlTest(unittest.TestCase):
    def setUp(self):
        priv = bitcoin.random_key()
        pub = bitcoin.privkey_to_pubkey(priv)
        pub_compressed = binascii.unhexlify(bitcoin.encode_pubkey(pub, "hex_compressed"))
        self.storage = ForgetfulStorage()
        self.protocol = KademliaProtocol(Node(digest("s"), pubkey=pub_compressed, merchant=True, serverPort=1234,
                                        transport=kprotocol.TCP), self.storage, 20)
        self.transport = proto_helpers.FakeDatagramTransport()
        self.protocol.transport = self.transport
        self.node1 = Node(digest("id1"), "127.0.0.1", 12345, pubkey=digest("key1"), merchant=True, serverPort=9999, transport=TCP)
        self.node2 = Node(digest("id2"), "127.0.0.1", 22222, pubkey=digest("key2"), merchant=True, serverPort=8888, transport=TCP)
        self.node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"), merchant=True, serverPort=0000, transport=TCP)

    def test_find(self):
        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)
        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = ValueSpiderCrawl(self.protocol, node, nearest, 20, 3)
        spider.find()
        self.assertTrue(len(self.transport.written) == 3)
        for d, timeout in self.protocol._outstanding.items():
            timeout[1].cancel()

    def test_nodesFound(self):
        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)
        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = ValueSpiderCrawl(self.protocol, node, nearest, 20, 3)
        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(), self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        spider._nodesFound(responses)
        self.assertTrue(len(self.transport.written) == 3)
        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(), self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        resp = spider._nodesFound(responses)
        self.assertTrue(resp is None)
        response = (False, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(), self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        spider._nodesFound(responses)
        self.assertTrue(len(spider.nearest) == 2)
        val = kprotocol.Value()
        val.contractID = digest("contractID")
        val.serializedNode = self.protocol.sourceNode.proto.SerializeToString()
        response = (True, ("value", val.SerializeToString()))
        responses = {self.node3.id: response}
        spider.nearestWithoutValue = NodeHeap(node, 1)
        value = spider._nodesFound(responses)
        self.assertEqual(value[0], val.SerializeToString())
        for d, timeout in self.protocol._outstanding.items():
            timeout[1].cancel()

    def test_handleFoundValues(self):
        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)
        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = ValueSpiderCrawl(self.protocol, node, nearest, 20, 3)
        val = kprotocol.Value()
        val.contractID = digest("contractID")
        val.serializedNode = self.node1.proto.SerializeToString()
        val1 = val.SerializeToString()
        value = spider._handleFoundValues([(val1,)])
        self.assertEqual(value[0], val.SerializeToString())
        val.serializedNode = self.node2.proto.SerializeToString()
        val2 = val.SerializeToString()
        found_values = [(val1,), (val1,), (val2,)]
        self.assertEqual(spider._handleFoundValues(found_values), (val1,))
        spider.nearestWithoutValue.push(self.node1)
        spider._handleFoundValues(found_values)
        self.assertTrue(len(self.transport.written) > 0)
        for d, timeout in self.protocol._outstanding.items():
            timeout[1].cancel()
        self.transport.written = []
        spider.nearestWithoutValue.push(self.node2)
        spider._handleFoundValues([("asdfsd",)])
        self.assertTrue(len(self.transport.written) == 0)

class NodeSpiderCrawlTest(unittest.TestCase):
    def setUp(self):
        priv = bitcoin.random_key()
        pub = bitcoin.privkey_to_pubkey(priv)
        pub_compressed = binascii.unhexlify(bitcoin.encode_pubkey(pub, "hex_compressed"))
        self.storage = ForgetfulStorage()
        self.protocol = KademliaProtocol(Node(digest("s"), pubkey=pub_compressed, merchant=True, serverPort=1234,
                                        transport=kprotocol.TCP), self.storage, 20)
        self.transport = proto_helpers.FakeDatagramTransport()
        self.protocol.transport = self.transport
        self.node1 = Node(digest("id1"), "127.0.0.1", 12345, pubkey=digest("key1"), merchant=True, serverPort=9999, transport=TCP)
        self.node2 = Node(digest("id2"), "127.0.0.1", 22222, pubkey=digest("key2"), merchant=True, serverPort=8888, transport=TCP)
        self.node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"), merchant=True, serverPort=0000, transport=TCP)

    def test_find(self):
        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)
        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = NodeSpiderCrawl(self.protocol, node, nearest, 20, 3)
        spider.find()
        self.assertTrue(len(self.transport.written) == 3)
        for d, timeout in self.protocol._outstanding.items():
            timeout[1].cancel()

    def test_nodesFound(self):
        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)
        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = NodeSpiderCrawl(self.protocol, node, nearest, 20, 3)
        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(), self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        spider._nodesFound(responses)
        self.assertTrue(len(self.transport.written) == 3)
        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(), self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        nodes = spider._nodesFound(responses)
        self.assertTrue(sorted(nodes) == sorted([self.node1, self.node2, self.node3]))
        response = (False, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(), self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        nodes = spider._nodesFound(responses)
        self.assertTrue(sorted(nodes) == sorted([self.node2, self.node3]))
        for d, timeout in self.protocol._outstanding.items():
            timeout[1].cancel()

class RPCFindResponseTest(unittest.TestCase):
    def test_happened(self):
        response = (True, ("value", "some_value"))
        r = RPCFindResponse(response)
        self.assertTrue(r.happened())
        response = (False, ("value", "some_value"))
        r = RPCFindResponse(response)
        self.assertFalse(r.happened())

    def test_hasValue(self):
        response = (True, ("value", "some_value"))
        r = RPCFindResponse(response)
        self.assertTrue(r.hasValue())
        response = (False, ("a node"))
        r = RPCFindResponse(response)
        self.assertFalse(r.hasValue())

    def test_getValue(self):
        response = (True, ("value", "some_value"))
        r = RPCFindResponse(response)
        self.assertEqual(r.getValue(), ("some_value",))

    def test_getNodeList(self):
        node1 = Node(digest("id1"), "127.0.0.1", 12345, pubkey=digest("key1"), merchant=True, serverPort=9999, transport=TCP)
        node2 = Node(digest("id2"), "127.0.0.1", 22222, pubkey=digest("key2"), merchant=True, serverPort=8888, transport=TCP)
        node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"))
        response = (True, (node1.proto.SerializeToString(), node2.proto.SerializeToString(), node3.proto.SerializeToString(), "sdfasdfsd"))
        r = RPCFindResponse(response)
        nodes = r.getNodeList()
        self.assertEqual(nodes[0].proto, node1.proto)
        self.assertEqual(nodes[1].proto, node2.proto)
        self.assertEqual(nodes[2].proto, node3.proto)
