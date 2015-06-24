__author__ = 'chris'

from twisted.trial import unittest

from dht.crawling import RPCFindResponse
from dht.node import Node
from dht.utils import digest
from dht.kprotocol import TCP

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
        node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"), merchant=True, serverPort=0000, transport=TCP)
        response = (True, (node1.proto.SerializeToString(), node2.proto.SerializeToString(), node3.proto.SerializeToString()))
        r = RPCFindResponse(response)
        nodes = r.getNodeList()
        self.assertEqual(nodes[0].proto, node1.proto)
        self.assertEqual(nodes[1].proto, node2.proto)
        self.assertEqual(nodes[2].proto, node3.proto)
