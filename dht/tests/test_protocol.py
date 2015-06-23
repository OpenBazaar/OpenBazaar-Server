__author__ = 'chris'
import bitcoin, binascii

from dht.protocol import KademliaProtocol
from dht.utils import digest
from dht.storage import ForgetfulStorage
from dht.node import Node
from dht import kprotocol

from twisted.trial import unittest
from twisted.test import proto_helpers


class KademliaProtocolTest(unittest.TestCase):
    def setUp(self):
        pubkey = binascii.unhexlify(bitcoin.encode_pubkey(bitcoin.privkey_to_pubkey(bitcoin.random_key()), "hex_compressed"))
        self.storage = ForgetfulStorage()
        self.protocol = KademliaProtocol(Node(digest("s"), pubkey=pubkey), self.storage, 20)
        self.transport = proto_helpers.FakeDatagramTransport()
        self.protocol.transport = self.transport

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
        m.arguments.append("Value")
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        for i in range(0, 3):
            del m.arguments[-1]
        m.arguments.append("True")
        msg, addr = self.transport.written[0]
        self.assertEqual(msg, m.SerializeToString())
        self.assertEqual(addr[1], 55555)
        self.assertTrue(self.storage.getSpecific("Keyword", "Key") == "Value")

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
