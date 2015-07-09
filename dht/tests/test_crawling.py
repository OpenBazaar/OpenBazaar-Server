__author__ = 'chris'
import binascii
import nacl.signing, nacl.hash
import mock

from binascii import unhexlify

from txrudp import packet, connection, rudp, constants

from twisted.internet import udp, address, task
from twisted.trial import unittest

from dht.crawling import RPCFindResponse, NodeSpiderCrawl, ValueSpiderCrawl
from dht.node import Node, NodeHeap
from dht.utils import digest
from dht.kprotocol import TCP
from dht.storage import ForgetfulStorage
from dht.protocol import KademliaProtocol
from dht import kprotocol


class ValueSpiderCrawlTest(unittest.TestCase):

    def setUp(self):
        self.public_ip = '123.45.67.89'
        self.port = 12345
        self.own_addr = (self.public_ip, self.port)
        self.addr1 = ('132.54.76.98', 54321)
        self.addr2 = ('231.76.45.89', 15243)
        self.addr3 = ("193.193.111.00", 99999)

        self.clock = task.Clock()
        connection.REACTOR.callLater = self.clock.callLater

        self.proto_mock = mock.Mock(spec_set=rudp.ConnectionMultiplexer)
        self.handler_mock = mock.Mock(spec_set=connection.Handler)
        self.con = connection.Connection(
            self.proto_mock,
            self.handler_mock,
            self.own_addr,
            self.addr1
        )

        valid_key = "1a5c8e67edb8d279d1ae32fa2da97e236b95e95c837dc8c3c7c2ff7a7cc29855"
        self.signing_key = nacl.signing.SigningKey(valid_key, encoder=nacl.encoding.HexEncoder)
        verify_key = self.signing_key.verify_key
        signed_pubkey = self.signing_key.sign(str(verify_key))
        h = nacl.hash.sha512(signed_pubkey)
        self.storage = ForgetfulStorage()
        self.node = Node(unhexlify(h[:40]), self.public_ip, self.port, signed_pubkey, True, 1234, kprotocol.TCP)
        self.protocol = KademliaProtocol(self.node, self.storage, 20)

        transport = mock.Mock(spec_set=udp.Port)
        ret_val = address.IPv4Address('UDP', self.public_ip, self.port)
        transport.attach_mock(mock.Mock(return_value=ret_val), 'getHost')
        self.protocol.makeConnection(transport)

        self.node1 = Node(digest("id1"), self.addr1[0], self.addr1[1], digest("key1"), True, 9999, TCP)
        self.node2 = Node(digest("id2"), self.addr2[0], self.addr2[1], digest("key2"), True, 8888, TCP)
        self.node3 = Node(digest("id3"), self.addr3[0], self.addr3[1], digest("key3"), True, 0000, TCP)

    def tearDown(self):
        self.con.shutdown()
        self.protocol.shutdown()

    def test_find(self):
        self._connecting_to_connected()
        self.protocol[self.addr1] = self.con
        self.protocol[self.addr2] = self.con
        self.protocol[self.addr3] = self.con

        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)

        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = ValueSpiderCrawl(self.protocol, node, nearest, 20, 3)
        spider.find()

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        self.assertEqual(len(self.proto_mock.send_datagram.call_args_list), 4)

    def test_nodesFound(self):
        self._connecting_to_connected()
        self.protocol[self.addr1] = self.con
        self.protocol[self.addr2] = self.con
        self.protocol[self.addr3] = self.con

        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)

        # test resonse with uncontacted nodes
        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = ValueSpiderCrawl(self.protocol, node, nearest, 20, 3)
        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(),
                           self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        spider._nodesFound(responses)
        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        self.assertEqual(len(self.proto_mock.send_datagram.call_args_list), 4)

        # test all been contacted
        spider = ValueSpiderCrawl(self.protocol, node, nearest, 20, 3)
        for peer in spider.nearest.getUncontacted():
            spider.nearest.markContacted(peer)
        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(),
                           self.node3.proto.SerializeToString()))
        responses = {self.node2.id: response}
        resp = spider._nodesFound(responses)
        self.assertTrue(resp is None)

        # test didn't happen
        spider = ValueSpiderCrawl(self.protocol, node, nearest, 20, 3)
        response = (False, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(),
                            self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        spider._nodesFound(responses)
        self.assertTrue(len(spider.nearest) == 2)

        # test got value
        val = kprotocol.Value()
        val.contractID = digest("contractID")
        val.serializedNode = self.protocol.sourceNode.proto.SerializeToString()
        response = (True, ("value", val.SerializeToString()))
        responses = {self.node3.id: response}
        spider.nearestWithoutValue = NodeHeap(node, 1)
        value = spider._nodesFound(responses)
        self.assertEqual(value[0], val.SerializeToString())

    def test_handleFoundValues(self):
        self._connecting_to_connected()
        self.protocol[self.addr1] = self.con

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

        # test handle multiple values
        val.serializedNode = self.node2.proto.SerializeToString()
        val2 = val.SerializeToString()
        found_values = [(val1,), (val1,), (val2,)]
        self.assertEqual(spider._handleFoundValues(found_values), (val1,))

        # test store value at nearest without value
        spider.nearestWithoutValue.push(self.node1)
        spider._handleFoundValues(found_values)
        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        self.assertTrue(len(self.proto_mock.send_datagram.call_args_list) > 1)
        self.proto_mock.send_datagram.call_args_list = []

    def _connecting_to_connected(self):
        remote_synack_packet = packet.Packet.from_data(
            42,
            self.con.own_addr,
            self.con.dest_addr,
            ack=0,
            syn=True
        )
        self.con.receive_packet(remote_synack_packet)

        self.clock.advance(0)
        connection.REACTOR.runUntilCurrent()

        self.next_remote_seqnum = 43

        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_syn_packet = packet.Packet.from_bytes(m_calls[0][0][0])
        seqnum = sent_syn_packet.sequence_number

        self.handler_mock.reset_mock()
        self.proto_mock.reset_mock()

        self.next_seqnum = seqnum + 1


class NodeSpiderCrawlTest(unittest.TestCase):

    def setUp(self):
        self.public_ip = '123.45.67.89'
        self.port = 12345
        self.own_addr = (self.public_ip, self.port)
        self.addr1 = ('132.54.76.98', 54321)
        self.addr2 = ('231.76.45.89', 15243)
        self.addr3 = ("193.193.111.00", 99999)

        self.clock = task.Clock()
        connection.REACTOR.callLater = self.clock.callLater

        self.proto_mock = mock.Mock(spec_set=rudp.ConnectionMultiplexer)
        self.handler_mock = mock.Mock(spec_set=connection.Handler)
        self.con = connection.Connection(
            self.proto_mock,
            self.handler_mock,
            self.own_addr,
            self.addr1
        )

        valid_key = "1a5c8e67edb8d279d1ae32fa2da97e236b95e95c837dc8c3c7c2ff7a7cc29855"
        self.signing_key = nacl.signing.SigningKey(valid_key, encoder=nacl.encoding.HexEncoder)
        verify_key = self.signing_key.verify_key
        signed_pubkey = self.signing_key.sign(str(verify_key))
        h = nacl.hash.sha512(signed_pubkey)
        self.storage = ForgetfulStorage()
        self.node = Node(unhexlify(h[:40]), self.public_ip, self.port, signed_pubkey, True, 1234, kprotocol.TCP)
        self.protocol = KademliaProtocol(self.node, self.storage, 20)

        transport = mock.Mock(spec_set=udp.Port)
        ret_val = address.IPv4Address('UDP', self.public_ip, self.port)
        transport.attach_mock(mock.Mock(return_value=ret_val), 'getHost')
        self.protocol.makeConnection(transport)

        self.node1 = Node(digest("id1"), self.addr1[0], self.addr1[1], digest("key1"), True, 9999, TCP)
        self.node2 = Node(digest("id2"), self.addr2[0], self.addr2[1], digest("key2"), True, 8888, TCP)
        self.node3 = Node(digest("id3"), self.addr3[0], self.addr3[1], digest("key3"), True, 0000, TCP)

    def test_find(self):
        self._connecting_to_connected()
        self.protocol[self.addr1] = self.con
        self.protocol[self.addr2] = self.con
        self.protocol[self.addr3] = self.con

        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)

        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = NodeSpiderCrawl(self.protocol, node, nearest, 20, 3)
        spider.find()

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        self.assertEqual(len(self.proto_mock.send_datagram.call_args_list), 4)

    def test_nodesFound(self):
        self._connecting_to_connected()
        self.protocol[self.addr1] = self.con
        self.protocol[self.addr2] = self.con
        self.protocol[self.addr3] = self.con

        self.protocol.router.addContact(self.node1)
        self.protocol.router.addContact(self.node2)
        self.protocol.router.addContact(self.node3)

        node = Node(digest("s"))
        nearest = self.protocol.router.findNeighbors(node)
        spider = NodeSpiderCrawl(self.protocol, node, nearest, 20, 3)
        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(),
                           self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        spider._nodesFound(responses)

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        self.assertEqual(len(self.proto_mock.send_datagram.call_args_list), 4)

        response = (True, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(),
                           self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        nodes = spider._nodesFound(responses)
        node_protos = []
        for n in nodes:
            node_protos.append(n.proto)

        self.assertTrue(self.node1.proto in node_protos)
        self.assertTrue(self.node2.proto in node_protos)
        self.assertTrue(self.node3.proto in node_protos)

        response = (False, (self.node1.proto.SerializeToString(), self.node2.proto.SerializeToString(),
                            self.node3.proto.SerializeToString()))
        responses = {self.node1.id: response}
        nodes = spider._nodesFound(responses)
        node_protos = []
        for n in nodes:
            node_protos.append(n.proto)

        self.assertTrue(self.node2.proto in node_protos)
        self.assertTrue(self.node3.proto in node_protos)

    def _connecting_to_connected(self):
        remote_synack_packet = packet.Packet.from_data(
            42,
            self.con.own_addr,
            self.con.dest_addr,
            ack=0,
            syn=True
        )
        self.con.receive_packet(remote_synack_packet)

        self.clock.advance(0)
        connection.REACTOR.runUntilCurrent()

        self.next_remote_seqnum = 43

        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_syn_packet = packet.Packet.from_bytes(m_calls[0][0][0])
        seqnum = sent_syn_packet.sequence_number

        self.handler_mock.reset_mock()
        self.proto_mock.reset_mock()

        self.next_seqnum = seqnum + 1


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
        response = (False, "a node")
        r = RPCFindResponse(response)
        self.assertFalse(r.hasValue())

    def test_getValue(self):
        response = (True, ("value", "some_value"))
        r = RPCFindResponse(response)
        self.assertEqual(r.getValue(), ("some_value",))

    def test_getNodeList(self):
        node1 = Node(digest("id1"), "127.0.0.1", 12345, signed_pubkey=digest("key1"), merchant=True, server_port=9999,
                     transport=TCP)
        node2 = Node(digest("id2"), "127.0.0.1", 22222, signed_pubkey=digest("key2"), merchant=True, server_port=8888,
                     transport=TCP)
        node3 = Node(digest("id3"), "127.0.0.1", 77777, signed_pubkey=digest("key3"))
        response = (True, (
            node1.proto.SerializeToString(), node2.proto.SerializeToString(), node3.proto.SerializeToString(),
            "sdfasdfsd"))
        r = RPCFindResponse(response)
        nodes = r.getNodeList()
        self.assertEqual(nodes[0].proto, node1.proto)
        self.assertEqual(nodes[1].proto, node2.proto)
        self.assertEqual(nodes[2].proto, node3.proto)
