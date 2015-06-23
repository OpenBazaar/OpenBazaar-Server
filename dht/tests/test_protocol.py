__author__ = 'chris'
import bitcoin, binascii, pyelliptic

from dht.protocol import KademliaProtocol
from dht.utils import digest
from dht.storage import ForgetfulStorage
from dht.node import Node
from dht import kprotocol

from twisted.trial import unittest
from twisted.test import proto_helpers


class KademliaProtocolTest(unittest.TestCase):
    def setUp(self):
        priv = bitcoin.random_key()
        pub = bitcoin.privkey_to_pubkey(priv)
        pub_compressed = binascii.unhexlify(bitcoin.encode_pubkey(pub, "hex_compressed"))
        pub_uncompressed = bitcoin.decode_pubkey(binascii.hexlify(pub_compressed), formt='hex_compressed')
        pubkey_hex = bitcoin.encode_pubkey(pub_uncompressed, formt="hex")
        pubkey_raw = bitcoin.changebase(pubkey_hex[2:],16,256,minlen=64)
        privkey = bitcoin.encode_privkey(priv, "bin")
        pubkey = '\x02\xca\x00 '+pubkey_raw[:32]+'\x00 '+pubkey_raw[32:]
        self.alice = pyelliptic.ECC(curve='secp256k1', pubkey=pubkey, raw_privkey=privkey)
        self.storage = ForgetfulStorage()
        self.protocol = KademliaProtocol(Node(digest("s"), pubkey=pub_compressed, merchant=True, serverPort=1234,
                                        transport=kprotocol.TCP), self.storage, 20)
        self.transport = proto_helpers.FakeDatagramTransport()
        self.protocol.transport = self.transport

    def test_invalid_datagram(self):
        self.assertFalse(self.protocol.datagramReceived("hi", ("127.0.0.1", 55555)))
        self.assertFalse(self.protocol.datagramReceived("hihihihihihihihihihihihihihihihi", ("127.0.0.1", 55555)))

    def test_rpc_ping(self):
        self.protocol.startProtocol()
        self.assertTrue(len(self.transport.written) == 0)
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("PING")
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        m.arguments.append(self.protocol.sourceNode.id)
        msg, addr = self.transport.written[0]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)

    def test_rpc_store(self):
        self.protocol.startProtocol()
        self.assertTrue(len(self.transport.written) == 0)
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("STORE")
        m.arguments.append("Keyword")
        m.arguments.append("Key")
        m.arguments.append(self.protocol.sourceNode.proto.SerializeToString())
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        for i in range(0, 3):
            del m.arguments[-1]
        m.arguments.append("True")
        msg, addr = self.transport.written[0]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)
        self.assertTrue(self.storage.getSpecific("Keyword", "Key") == self.protocol.sourceNode.proto.SerializeToString())

    def test_rpc_delete(self):
        self.protocol.startProtocol()
        self.assertTrue(len(self.transport.written) == 0)
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("STORE")
        m.arguments.append("Keyword")
        m.arguments.append("Key")
        m.arguments.append(self.protocol.sourceNode.proto.SerializeToString())
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("DELETE")
        m.arguments.append("Keyword")
        m.arguments.append("Key")
        m.arguments.append(self.alice.sign("Key"))
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        for i in range(0, 3):
            del m.arguments[-1]
        m.arguments.append("True")
        msg, addr = self.transport.written[1]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)
        self.assertTrue(self.storage.getSpecific("Keyword", "Key") is None)

    def test_rpc_stun(self):
        self.protocol.startProtocol()
        self.assertTrue(len(self.transport.written) == 0)
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("STUN")
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        node = kprotocol.Node()
        node.guid = self.protocol.sourceNode.id
        node.ip = "127.0.0.1"
        node.port = 55555
        node.publicKey = self.protocol.sourceNode.pubkey
        m.arguments.append(node.SerializeToString())
        msg, addr = self.transport.written[0]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)

    def test_rpc_find_node(self):
        self.protocol.startProtocol()
        node1 = Node(digest("id1"), "127.0.0.1", 12345, pubkey=digest("key1"))
        node2 = Node(digest("id2"), "127.0.0.1", 22222, pubkey=digest("key2"))
        node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"))
        self.protocol.router.addContact(node1)
        self.protocol.router.addContact(node2)
        self.protocol.router.addContact(node3)
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("FIND_NODE")
        m.arguments.append(digest("nodetofind"))
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        del m.arguments[-1]
        m.arguments.append(node3.proto.SerializeToString())
        m.arguments.append(node2.proto.SerializeToString())
        m.arguments.append(node1.proto.SerializeToString())
        msg, addr = self.transport.written[0]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)

    def test_rpc_find_value(self):
        self.protocol.startProtocol()
        self.assertTrue(len(self.transport.written) == 0)
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("STORE")
        m.arguments.append("Keyword")
        m.arguments.append("Key")
        m.arguments.append(self.protocol.sourceNode.proto.SerializeToString())
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("FIND_VALUE")
        m.arguments.append("Keyword")
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        del m.arguments[-1]
        value = kprotocol.Value()
        value.contractID = "Key"
        value.serializedNode = self.protocol.sourceNode.proto.SerializeToString()
        m.arguments.append("value")
        m.arguments.append(value.SerializeToString())
        msg, addr = self.transport.written[1]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)

    def test_rpc_find_without_value(self):
        self.protocol.startProtocol()
        node1 = Node(digest("id1"), "127.0.0.1", 12345, pubkey=digest("key1"))
        node2 = Node(digest("id2"), "127.0.0.1", 22222, pubkey=digest("key2"))
        node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"))
        self.protocol.router.addContact(node1)
        self.protocol.router.addContact(node2)
        self.protocol.router.addContact(node3)
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("FIND_VALUE")
        m.arguments.append(digest("nodetofind"))
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        del m.arguments[-1]
        m.arguments.append(node3.proto.SerializeToString())
        m.arguments.append(node2.proto.SerializeToString())
        m.arguments.append(node1.proto.SerializeToString())
        msg, addr = self.transport.written[0]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)
