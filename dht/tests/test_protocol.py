__author__ = 'chris'
import bitcoin, binascii, pyelliptic, time

from dht.protocol import KademliaProtocol
from dht.utils import digest
from dht.storage import ForgetfulStorage
from dht.node import Node
from dht import kprotocol

from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import task, reactor


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
        # Set a keyword to store
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("STORE")
        m.arguments.append("Keyword")
        m.arguments.append("Key")
        m.arguments.append(self.protocol.sourceNode.proto.SerializeToString())
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        # Test bad signature
        m = kprotocol.Message()
        m.messageID = digest("msgid")
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("DELETE")
        m.arguments.append("Keyword")
        m.arguments.append("Key")
        m.arguments.append("Bad Signature")
        data = m.SerializeToString()
        self.protocol.datagramReceived(data, ("127.0.0.1", 55555))
        for i in range(0, 3):
            del m.arguments[-1]
        m.arguments.append("False")
        msg, addr = self.transport.written[1]
        self.assertEqual(msg, m.SerializeToString())
        # Test good signature
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
        msg, addr = self.transport.written[2]
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

    def test_callPing(self):
        self.protocol.startProtocol()
        n = Node(digest("S"), "127.0.0.1", 55555)
        self.protocol.callPing(n)
        msg, addr = self.transport.written[0]
        m = kprotocol.Message()
        m.ParseFromString(msg)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.proto.guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.proto.publicKey, m.sender.publicKey)
        self.assertTrue(m.command == kprotocol.PING)
        self.assertEqual(addr[1], 55555)
        d, timeout = self.protocol._outstanding[m.messageID]
        timeout.cancel()

    def test_callStore(self):
        self.protocol.startProtocol()
        n = Node(digest("S"), "127.0.0.1", 55555)
        self.protocol.callStore(n, digest("Keyword"), digest("Key"), self.protocol.sourceNode.proto.SerializeToString())
        msg, addr = self.transport.written[0]
        m = kprotocol.Message()
        m.ParseFromString(msg)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.proto.guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.proto.publicKey, m.sender.publicKey)
        self.assertTrue(m.command == kprotocol.STORE)
        self.assertEqual(m.arguments[0], digest("Keyword"))
        self.assertEqual(m.arguments[1], digest("Key"))
        self.assertEqual(m.arguments[2], self.protocol.sourceNode.proto.SerializeToString())
        self.assertEqual(addr[1], 55555)
        d, timeout = self.protocol._outstanding[m.messageID]
        timeout.cancel()

    def test_callFindValue(self):
        self.protocol.startProtocol()
        n = Node(digest("S"), "127.0.0.1", 55555)
        keyword = Node(digest("Keyword"))
        self.protocol.callFindValue(n, keyword)
        msg, addr = self.transport.written[0]
        m = kprotocol.Message()
        m.ParseFromString(msg)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.proto.guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.proto.publicKey, m.sender.publicKey)
        self.assertTrue(m.command == kprotocol.FIND_VALUE)
        self.assertEqual(m.arguments[0], keyword.id)
        self.assertEqual(addr[1], 55555)
        d, timeout = self.protocol._outstanding[m.messageID]
        timeout.cancel()

    def test_callFindNode(self):
        self.protocol.startProtocol()
        n = Node(digest("S"), "127.0.0.1", 55555)
        keyword = Node(digest("nodetofind"))
        self.protocol.callFindNode(n, keyword)
        msg, addr = self.transport.written[0]
        m = kprotocol.Message()
        m.ParseFromString(msg)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.proto.guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.proto.publicKey, m.sender.publicKey)
        self.assertTrue(m.command == kprotocol.FIND_NODE)
        self.assertEqual(m.arguments[0], keyword.id)
        self.assertEqual(addr[1], 55555)
        d, timeout = self.protocol._outstanding[m.messageID]
        timeout.cancel()

    def test_callDelete(self):
        self.protocol.startProtocol()
        n = Node(digest("S"), "127.0.0.1", 55555)
        self.protocol.callDelete(n, digest("Keyword"), digest("Key"), digest("Signature"))
        msg, addr = self.transport.written[0]
        m = kprotocol.Message()
        m.ParseFromString(msg)
        self.assertTrue(len(m.messageID) == 20)
        self.assertEqual(self.protocol.sourceNode.proto.guid, m.sender.guid)
        self.assertEqual(self.protocol.sourceNode.proto.publicKey, m.sender.publicKey)
        self.assertTrue(m.command == kprotocol.DELETE)
        self.assertEqual(m.arguments[0], digest("Keyword"))
        self.assertEqual(m.arguments[1], digest("Key"))
        self.assertEqual(m.arguments[2], digest("Signature"))
        self.assertEqual(addr[1], 55555)
        d, timeout = self.protocol._outstanding[m.messageID]
        timeout.cancel()

    def test_acceptResponse(self):
        self.protocol.startProtocol()
        def handle_response(resp):
            self.assertTrue(resp[0])
            self.assertEqual(resp[1][0], self.protocol.sourceNode.id)
        n = Node(digest("S"), "127.0.0.1", 55555)
        d = self.protocol.callPing(n)
        msg, addr = self.transport.written[0]
        m = kprotocol.Message()
        m.ParseFromString(msg)
        m.arguments.append(self.protocol.sourceNode.id)
        self.protocol.datagramReceived(m.SerializeToString(), ("127.0.0.1", 55555))
        return d.addCallback(handle_response)

    def test_unknownRPC(self):
        self.protocol.startProtocol()
        self.assertFalse(self.protocol._acceptRequest(digest("msgid"), "unknown",
                                                      [digest("argument")], Node(digest("nodeid"))))

    def test_timeout(self):
        def test_remove_outstanding():
            self.assertTrue(len(self.protocol._outstanding) == 0)
        def test_deffered(d):
            self.assertFalse(d[0])
        self.protocol.startProtocol()
        n = Node(digest("S"), "127.0.0.1", 55555)
        d = self.protocol.callPing(n)
        d.addCallback(test_deffered)
        return task.deferLater(reactor, 5.00001, test_remove_outstanding)

    def test_transferKeyValues(self):
        self.protocol.storage[digest("keyword")] = (digest("key"), self.protocol.sourceNode.proto.SerializeToString())
        node1 = Node(digest("id1"), "127.0.0.1", 12345, pubkey=digest("key1"))
        node2 = Node(digest("id2"), "127.0.0.1", 22222, pubkey=digest("key2"))
        node3 = Node(digest("id3"), "127.0.0.1", 77777, pubkey=digest("key3"))
        self.protocol.router.addContact(node1)
        self.protocol.router.addContact(node2)
        self.protocol.router.addContact(node3)
        self.protocol.transferKeyValues(Node(digest("id"), "127.0.0.1", 99999))
        msg, addr = self.transport.written[0]
        x = kprotocol.Message()
        x.ParseFromString(msg)
        m = kprotocol.Message()
        m.sender.MergeFrom(self.protocol.sourceNode.proto)
        m.command = kprotocol.Command.Value("STORE")
        m.arguments.append(digest("keyword"))
        m.arguments.append(digest("key"))
        m.arguments.append(self.protocol.sourceNode.proto.SerializeToString())
        self.assertEqual(x.sender, m.sender)
        self.assertEqual(x.command, m.command)
        self.assertEqual(x.arguments[0], m.arguments[0])
        self.assertEqual(x.arguments[1], m.arguments[1])
        self.assertEqual(x.arguments[2], m.arguments[2])
        for d, timeout in self.protocol._outstanding.items():
            timeout[1].cancel()

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
        self.assertTrue(len(ids)==1)