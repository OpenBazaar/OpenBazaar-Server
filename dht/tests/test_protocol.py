__author__ = 'chris'
import time
import random
from binascii import unhexlify

import mock
import nacl.signing
import nacl.encoding
import nacl.hash
import os
from txrudp import connection, rudp, packet, constants
from twisted.trial import unittest
from twisted.internet import task, address, udp, defer, reactor

from dht.protocol import KademliaProtocol
from dht.utils import digest
from dht.storage import ForgetfulStorage
from dht.node import Node
from protos import message, objects
from net.wireprotocol import OpenBazaarProtocol
from db import datastore
from config import PROTOCOL_VERSION


class KademliaProtocolTest(unittest.TestCase):
    def setUp(self):
        self.version = PROTOCOL_VERSION
        self.public_ip = '123.45.67.89'
        self.port = 12345
        self.own_addr = (self.public_ip, self.port)
        self.addr1 = ('132.54.76.98', 54321)
        self.addr2 = ('231.76.45.89', 15243)

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

        valid_key = "63d901c4d57cde34fc1f1e28b9af5d56ed342cae5c2fb470046d0130a4226b0c"
        self.signing_key = nacl.signing.SigningKey(valid_key, encoder=nacl.encoding.HexEncoder)
        verify_key = self.signing_key.verify_key
        h = nacl.hash.sha512(verify_key.encode())
        self.storage = ForgetfulStorage()
        self.node = Node(unhexlify(h[:40]), self.public_ip, self.port,
                         verify_key.encode(), None, objects.FULL_CONE, True)
        self.db = datastore.Database(filepath="test.db")
        self.protocol = KademliaProtocol(self.node, self.storage, 20, self.db, self.signing_key)

        self.wire_protocol = OpenBazaarProtocol(self.db, self.own_addr, objects.FULL_CONE)
        self.wire_protocol.register_processor(self.protocol)

        self.protocol.connect_multiplexer(self.wire_protocol)
        self.handler = self.wire_protocol.ConnHandler([self.protocol], self.wire_protocol, None,
                                                      self.wire_protocol.ban_score)
        self.handler.connection = self.con

        transport = mock.Mock(spec_set=udp.Port)
        ret_val = address.IPv4Address('UDP', self.public_ip, self.port)
        transport.attach_mock(mock.Mock(return_value=ret_val), 'getHost')
        self.wire_protocol.makeConnection(transport)

    def tearDown(self):
        if self.con.state != connection.State.SHUTDOWN:
            self.con.shutdown()
        self.wire_protocol.shutdown()
        os.remove("test.db")

    def test_invalid_datagram(self):
        self.assertFalse(self.handler.receive_message("hi"))
        self.assertFalse(self.handler.receive_message("hihihihihihihihihihihihihihihihihihihihih"))

    def test_rpc_ping(self):
        self._connecting_to_connected()

        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("PING")
        m.protoVer = self.version
        m.testnet = False
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        m.arguments.append(self.protocol.sourceNode.getProto().SerializeToString())
        m.ClearField("signature")
        expected_message = m.SerializeToString()
        self.handler.on_connection_made()
        self.handler.receive_message(data)

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        received_message = sent_packet.payload
        m2 = message.Message()
        m2.ParseFromString(received_message)
        m2.ClearField("signature")
        received_message = m2.SerializeToString()

        self.assertEqual(received_message, expected_message)
        self.assertEqual(len(m_calls), 2)

    def test_rpc_store(self):
        self._connecting_to_connected()
        self.protocol.router.addContact(self.protocol.sourceNode)

        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("STORE")
        m.protoVer = self.version
        m.testnet = False
        m.arguments.extend([digest("Keyword"), "Key",
                            self.protocol.sourceNode.getProto().SerializeToString(), str(10)])
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        del m.arguments[-4:]
        m.arguments.append("True")
        m.ClearField("signature")
        expected_message = m.SerializeToString()
        self.handler.on_connection_made()
        self.handler.receive_message(data)

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        received_message = sent_packet.payload
        m2 = message.Message()
        m2.ParseFromString(received_message)
        m2.ClearField("signature")
        received_message = m2.SerializeToString()
        self.assertEqual(received_message, expected_message)
        self.assertEqual(len(m_calls), 2)
        self.assertTrue(
            self.storage.getSpecific(digest("Keyword"), "Key") ==
            self.protocol.sourceNode.getProto().SerializeToString())

    def test_bad_rpc_store(self):
        r = self.protocol.rpc_store(self.node, 'testkeyword', 'kw', 'val', 10)
        self.assertEqual(r, ['False'])

    def test_rpc_delete(self):
        self._connecting_to_connected()
        self.protocol.router.addContact(self.protocol.sourceNode)

        # Set a keyword to store
        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("STORE")
        m.protoVer = self.version
        m.testnet = False
        m.arguments.extend([digest("Keyword"), "Key",
                            self.protocol.sourceNode.getProto().SerializeToString(), str(10)])
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        del m.arguments[-4:]
        m.arguments.append("True")
        m.ClearField("signature")
        expected_message1 = m.SerializeToString()
        self.handler.on_connection_made()
        self.handler.receive_message(data)
        self.assertTrue(
            self.storage.getSpecific(digest("Keyword"), "Key") ==
            self.protocol.sourceNode.getProto().SerializeToString())

        # Test bad signature
        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("DELETE")
        m.protoVer = self.version
        m.testnet = False
        m.arguments.extend([digest("Keyword"), "Key", "Bad Signature"])
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        del m.arguments[-3:]
        m.arguments.append("False")
        m.ClearField("signature")
        expected_message2 = m.SerializeToString()
        self.handler.receive_message(data)
        self.assertTrue(
            self.storage.getSpecific(digest("Keyword"), "Key") ==
            self.protocol.sourceNode.getProto().SerializeToString())

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        sent_packets = tuple(
            packet.Packet.from_bytes(call[0][0])
            for call in self.proto_mock.send_datagram.call_args_list
        )
        m2 = message.Message()
        m2.ParseFromString(sent_packets[0].payload)
        m2.ClearField("signature")
        received_message1 = m2.SerializeToString()
        m3 = message.Message()
        m3.ParseFromString(sent_packets[1].payload)
        m3.ClearField("signature")
        received_message2 = m3.SerializeToString()
        self.assertEqual(received_message1, expected_message1)
        self.assertEqual(received_message2, expected_message2)
        self.proto_mock.send_datagram.call_args_list = []

        # Test good signature
        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("DELETE")
        m.protoVer = self.version
        m.testnet = False
        m.arguments.extend([digest("Keyword"), "Key", self.signing_key.sign("Key")[:64]])
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        del m.arguments[-3:]
        m.arguments.append("True")
        m.ClearField("signature")
        expected_message3 = m.SerializeToString()
        self.handler.receive_message(data)
        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        m4 = message.Message()
        m4.ParseFromString(sent_packet.payload)
        m4.ClearField("signature")
        received_message = m4.SerializeToString()
        self.assertEqual(received_message, expected_message3)
        self.assertTrue(self.storage.getSpecific(digest("Keyword"), "Key") is None)

    def test_rpc_stun(self):
        self._connecting_to_connected()

        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("STUN")
        m.protoVer = self.version
        m.testnet = False
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        m.arguments.extend([self.public_ip, str(self.port)])
        m.ClearField("signature")
        expected_message = m.SerializeToString()
        self.handler.on_connection_made()
        self.handler.receive_message(data)

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        received_message = sent_packet.payload
        a = message.Message()
        a.ParseFromString(received_message)
        a.ClearField("signature")
        received_message = a.SerializeToString()
        self.assertEqual(received_message, expected_message)
        self.assertEqual(len(m_calls), 2)

    def test_rpc_find_node(self):
        self._connecting_to_connected()

        node1 = Node(digest("id1"), "127.0.0.1", 12345, digest("key1"), nat_type=objects.FULL_CONE)
        node2 = Node(digest("id2"), "127.0.0.1", 22222, digest("key2"), nat_type=objects.FULL_CONE)
        node3 = Node(digest("id3"), "127.0.0.1", 77777, digest("key3"), nat_type=objects.FULL_CONE)
        self.protocol.router.addContact(node1)
        self.protocol.router.addContact(node2)
        self.protocol.router.addContact(node3)
        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("FIND_NODE")
        m.protoVer = self.version
        m.testnet = False
        m.arguments.append(digest("nodetofind"))
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        del m.arguments[-1]
        m.arguments.extend([node2.getProto().SerializeToString(), node1.getProto().SerializeToString(),
                            node3.getProto().SerializeToString()])
        m.ClearField("signature")
        expected_message = m.SerializeToString()
        self.handler.on_connection_made()
        self.handler.receive_message(data)

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        received_message = sent_packet.payload
        a = message.Message()
        a.ParseFromString(received_message)
        a.ClearField("signature")
        received_message = a.SerializeToString()
        self.assertEqual(received_message, expected_message)
        self.assertEqual(len(m_calls), 2)

    def test_rpc_find_value(self):
        self._connecting_to_connected()
        self.protocol.router.addContact(self.protocol.sourceNode)

        # Set a value to find
        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("STORE")
        m.protoVer = self.version
        m.arguments.extend([digest("Keyword"), "Key",
                            self.protocol.sourceNode.getProto().SerializeToString(), str(10)])
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        self.handler.on_connection_made()
        self.handler.receive_message(data)
        self.assertTrue(
            self.storage.getSpecific(digest("Keyword"), "Key") ==
            self.protocol.sourceNode.getProto().SerializeToString())

        # Send the find_value rpc
        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("FIND_VALUE")
        m.protoVer = self.version
        m.testnet = False
        m.arguments.append(digest("Keyword"))
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        self.handler.receive_message(data)

        del m.arguments[-1]
        value = objects.Value()
        value.valueKey = "Key"
        value.serializedData = self.protocol.sourceNode.getProto().SerializeToString()
        value.ttl = 10
        m.arguments.append("value")
        m.arguments.append(value.SerializeToString())
        m.ClearField("signature")
        expected_message = m.SerializeToString()

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_packets = tuple(
            packet.Packet.from_bytes(call[0][0])
            for call in self.proto_mock.send_datagram.call_args_list
        )
        received_message = sent_packets[1].payload
        a = message.Message()
        a.ParseFromString(received_message)
        a.ClearField("signature")
        received_message = a.SerializeToString()

        self.assertEqual(received_message, expected_message)
        self.assertEqual(len(m_calls), 3)

    def test_rpc_find_without_value(self):
        self._connecting_to_connected()

        node1 = Node(digest("id1"), "127.0.0.1", 12345, digest("key1"), nat_type=objects.FULL_CONE)
        node2 = Node(digest("id2"), "127.0.0.1", 22222, digest("key2"), nat_type=objects.FULL_CONE)
        node3 = Node(digest("id3"), "127.0.0.1", 77777, digest("key3"), nat_type=objects.FULL_CONE)
        self.protocol.router.addContact(node1)
        self.protocol.router.addContact(node2)
        self.protocol.router.addContact(node3)
        m = message.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("FIND_VALUE")
        m.protoVer = self.version
        m.testnet = False
        m.arguments.append(digest("Keyword"))
        m.signature = self.signing_key.sign(m.SerializeToString())[:64]
        data = m.SerializeToString()
        self.handler.on_connection_made()
        self.handler.receive_message(data)

        del m.arguments[-1]
        m.arguments.extend([node3.getProto().SerializeToString(), node1.getProto().SerializeToString(),
                            node2.getProto().SerializeToString()])
        m.ClearField("signature")
        expected_message = m.SerializeToString()

        self.clock.advance(100 * constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        received_message = sent_packet.payload
        a = message.Message()
        a.ParseFromString(received_message)
        a.ClearField("signature")
        received_message = a.SerializeToString()

        self.assertEqual(received_message, expected_message)
        self.assertEqual(len(m_calls), 2)

    def test_callPing(self):
        self._connecting_to_connected()

        n = Node(digest("guid"), self.addr1[0], self.addr1[1], digest("pubkey"), None, objects.FULL_CONE, False)
        self.wire_protocol[self.addr1] = self.con
        self.protocol.callPing(n)

        self.clock.advance(constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        sent_message = sent_packet.payload

        m = message.Message()
        m.ParseFromString(sent_message)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.getProto().guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.getProto().publicKey, m.sender.publicKey)
        self.assertTrue(m.command == message.PING)
        self.assertEqual(self.proto_mock.send_datagram.call_args_list[0][0][1], self.addr1)

    def test_callStore(self):
        self._connecting_to_connected()

        n = Node(digest("guid"), self.addr1[0], self.addr1[1], digest("pubkey"), None, objects.FULL_CONE, False)
        self.wire_protocol[self.addr1] = self.con
        self.protocol.callStore(n, digest("Keyword"), digest("Key"),
                                self.protocol.sourceNode.getProto().SerializeToString(), 10)

        self.clock.advance(constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        sent_message = sent_packet.payload

        m = message.Message()
        m.ParseFromString(sent_message)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.getProto().guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.getProto().publicKey, m.sender.publicKey)
        self.assertTrue(m.command == message.STORE)
        self.assertEqual(self.proto_mock.send_datagram.call_args_list[0][0][1], self.addr1)
        self.assertEqual(m.arguments[0], digest("Keyword"))
        self.assertEqual(m.arguments[1], digest("Key"))
        self.assertEqual(m.arguments[2], self.protocol.sourceNode.getProto().SerializeToString())

    def test_callFindValue(self):
        self._connecting_to_connected()

        n = Node(digest("S"), self.addr1[0], self.addr1[1])
        self.wire_protocol[self.addr1] = self.con
        keyword = Node(digest("Keyword"))
        self.protocol.callFindValue(n, keyword)

        self.clock.advance(constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        sent_message = sent_packet.payload

        m = message.Message()
        m.ParseFromString(sent_message)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.getProto().guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.getProto().publicKey, m.sender.publicKey)
        self.assertTrue(m.command == message.FIND_VALUE)
        self.assertEqual(self.proto_mock.send_datagram.call_args_list[0][0][1], self.addr1)
        self.assertEqual(m.arguments[0], keyword.id)

    def test_callFindNode(self):
        self._connecting_to_connected()

        n = Node(digest("S"), self.addr1[0], self.addr1[1])
        self.wire_protocol[self.addr1] = self.con
        keyword = Node(digest("nodetofind"))
        self.protocol.callFindNode(n, keyword)

        self.clock.advance(constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        sent_message = sent_packet.payload

        m = message.Message()
        m.ParseFromString(sent_message)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.getProto().guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.getProto().publicKey, m.sender.publicKey)
        self.assertTrue(m.command == message.FIND_NODE)
        self.assertEqual(self.proto_mock.send_datagram.call_args_list[0][0][1], self.addr1)
        self.assertEqual(m.arguments[0], keyword.id)

    def test_callDelete(self):
        self._connecting_to_connected()

        n = Node(digest("S"), self.addr1[0], self.addr1[1])
        self.wire_protocol[self.addr1] = self.con
        self.protocol.callDelete(n, digest("Keyword"), digest("Key"), digest("Signature"))

        self.clock.advance(constants.PACKET_TIMEOUT)
        connection.REACTOR.runUntilCurrent()
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        sent_message = sent_packet.payload

        m = message.Message()
        m.ParseFromString(sent_message)
        self.assertEqual(self.proto_mock.send_datagram.call_args_list[0][0][1], self.addr1)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.getProto().guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.getProto().publicKey, m.sender.publicKey)
        self.assertTrue(m.command == message.DELETE)
        self.assertEqual(m.arguments[0], digest("Keyword"))
        self.assertEqual(m.arguments[1], digest("Key"))
        self.assertEqual(m.arguments[2], digest("Signature"))

    def test_acceptResponse(self):
        self._connecting_to_connected()

        def handle_response(resp):
            self.assertTrue(resp[0])
            self.assertEqual(resp[1][0], "test")
            self.assertTrue(message_id not in self.protocol._outstanding)

        message_id = digest("msgid")
        n = Node(digest("S"), self.addr1[0], self.addr1[1])
        d = defer.Deferred()
        self.protocol._outstanding[message_id] = (d, self.addr1, reactor.callLater(5, handle_response))
        self.protocol._acceptResponse(message_id, ["test"], n)

        return d.addCallback(handle_response)

    def test_unknownRPC(self):
        self.assertFalse(self.handler.receive_message(str(random.getrandbits(1400))))

    def test_timeout(self):

        def handle_response(resp, n):
            self.assertFalse(resp[0])
            self.assertIsNone(resp[1])

        n = Node(digest("S"), self.addr1[0], self.addr1[1])
        d = defer.Deferred().addCallback(handle_response, n)
        self.protocol._outstanding["msgID"] = [d, self.addr1, reactor.callLater(5, handle_response)]
        self.protocol.router.addContact(n)
        self.protocol.timeout(n)

    def test_transferKeyValues(self):
        self._connecting_to_connected()
        self.wire_protocol[self.addr1] = self.con

        self.protocol.storage[digest("keyword")] = (
            digest("key"), self.protocol.sourceNode.getProto().SerializeToString(), 10)
        self.protocol.storage[digest("keyword")] = (
            digest("key2"), self.protocol.sourceNode.getProto().SerializeToString(), 10)

        self.protocol.transferKeyValues(Node(digest("id"), self.addr1[0], self.addr1[1]))

        self.clock.advance(1)
        connection.REACTOR.runUntilCurrent()
        sent_packet = packet.Packet.from_bytes(self.proto_mock.send_datagram.call_args_list[0][0][0])
        sent_message = sent_packet.payload
        x = message.Message()
        x.ParseFromString(sent_message)

        i = objects.Inv()
        i.keyword = digest("keyword")
        i.valueKey = digest("key")

        i2 = objects.Inv()
        i2.keyword = digest("keyword")
        i2.valueKey = digest("key2")

        m = message.Message()
        m.sender.MergeFrom(self.protocol.sourceNode.getProto())
        m.command = message.Command.Value("INV")
        m.protoVer = self.version
        m.arguments.append(i.SerializeToString())
        m.arguments.append(i2.SerializeToString())
        self.assertEqual(x.sender.guid, m.sender.guid)
        self.assertEqual(x.command, m.command)
        self.assertTrue(x.arguments[0] in m.arguments)
        self.assertTrue(x.arguments[1] in m.arguments)

    def test_refreshIDs(self):
        node1 = Node(digest("id1"), "127.0.0.1", 12345, pubkey=digest("key1"))
        node2 = Node(digest("id2"), "127.0.0.1", 22222, pubkey=digest("key2"))
        node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"))
        self.protocol.router.addContact(node1)
        self.protocol.router.addContact(node2)
        self.protocol.router.addContact(node3)
        for b in self.protocol.router.buckets:
            b.lastUpdated = (time.time() - 5000)
        ids = self.protocol.getRefreshIDs()
        self.assertTrue(len(ids) == 1)

    def _connecting_to_connected(self):
        remote_synack_packet = packet.Packet.from_data(
            42,
            self.con.own_addr,
            self.con.dest_addr,
            ack=0,
            syn=True
        )
        self.con.receive_packet(remote_synack_packet, self.addr1)

        self.clock.advance(0)
        connection.REACTOR.runUntilCurrent()

        self.next_remote_seqnum = 43

        m_calls = self.proto_mock.send_datagram.call_args_list
        sent_syn_packet = packet.Packet.from_bytes(m_calls[0][0][0])
        seqnum = sent_syn_packet.sequence_number

        self.handler_mock.reset_mock()
        self.proto_mock.reset_mock()

        self.next_seqnum = seqnum + 1

    def test_badRPCDelete(self):
        n = Node(digest("S"), self.addr1[0], self.addr1[1])
        val = self.protocol.rpc_delete(n, 'testkeyword', 'key', 'testsig')
        self.assertEqual(val, ["False"])
        val = self.protocol.rpc_delete(n, '', '', '')
