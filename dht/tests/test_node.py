import random
import hashlib

from twisted.trial import unittest

from dht.node import Node, NodeHeap
from dht.tests.utils import mknode
from dht.utils import digest

from protos import objects


class NodeTest(unittest.TestCase):
    def test_longID(self):
        rid = hashlib.sha1(str(random.getrandbits(255))).digest()
        n = Node(rid)
        self.assertEqual(n.long_id, int(rid.encode('hex'), 16))

    def test_distanceCalculation(self):
        ridone = hashlib.sha1(str(random.getrandbits(255)))
        ridtwo = hashlib.sha1(str(random.getrandbits(255)))

        shouldbe = int(ridone.hexdigest(), 16) ^ int(ridtwo.hexdigest(), 16)
        none = Node(ridone.digest())
        ntwo = Node(ridtwo.digest())
        self.assertEqual(none.distanceTo(ntwo), shouldbe)

    def test_create_proto(self):
        rid = hashlib.sha1(str(random.getrandbits(255))).digest()
        pubkey = digest("pubkey")

        addr = objects.Node.IPAddress()
        addr.ip = "127.0.0.1"
        addr.port = 1234

        relay_addr = objects.Node.IPAddress()
        relay_addr.ip = "127.0.0.1"
        relay_addr.port = 1234

        n1 = objects.Node()
        n1.guid = rid
        n1.publicKey = pubkey
        n1.vendor = False
        n1.nodeAddress.MergeFrom(addr)
        n1.natType = objects.FULL_CONE
        n2 = Node(rid, "127.0.0.1", 1234, digest("pubkey"), None, objects.FULL_CONE, False)
        self.assertEqual(n1, n2.getProto())

        n1.vendor = True
        n1.relayAddress.MergeFrom(relay_addr)
        n2 = Node(rid, "127.0.0.1", 1234, digest("pubkey"), ("127.0.0.1", 1234), objects.FULL_CONE, True)
        self.assertEqual(n1, n2.getProto())

    def test_tuple(self):
        n = Node('127.0.0.1', 0, 'testkey')
        i = n.__iter__()
        self.assertIn('127.0.0.1', i)
        self.assertIn(0, i)
        self.assertIn('testkey', i)


class NodeHeapTest(unittest.TestCase):
    def test_maxSize(self):
        n = NodeHeap(mknode(intid=0), 3)
        self.assertEqual(0, len(n))

        for d in range(10):
            n.push(mknode(intid=d))
        self.assertEqual(3, len(n))

        self.assertEqual(3, len(list(n)))

    def test_iteration(self):
        heap = NodeHeap(mknode(intid=0), 5)
        nodes = [mknode(intid=x) for x in range(10)]
        for index, node in enumerate(nodes):
            heap.push(node)
        for index, node in enumerate(heap):
            self.assertEqual(index, node.long_id)
            self.assertTrue(index < 5)

    def test_remove(self):
        heap = NodeHeap(mknode(intid=0), 5)
        nodes = [mknode(intid=x) for x in range(10)]
        for node in nodes:
            heap.push(node)

        heap.remove([nodes[0].id, nodes[1].id])
        self.assertEqual(len(list(heap)), 5)
        for index, node in enumerate(heap):
            self.assertEqual(index + 2, node.long_id)
            self.assertTrue(index < 5)

    def test_getNoneNodeById(self):
        n = Node('127.0.0.1', 0, 'testkey')
        nh = NodeHeap(n, 5)
        val = nh.getNodeById('')
        self.assertIsNone(val)
