from twisted.trial import unittest
from twisted.python import log

from dht.node import Node
from dht.utils import digest
from dht.routing import RoutingTable
from market.protocol import MarketProtocol
from dht.tests.utils import mknode

class MarketProtocolTest(unittest.TestCase):
    def setUp(self):
        self.catcher = []
        observer = self.catcher.append
        log.addObserver(observer)
        self.addCleanup(log.removeObserver, observer)
        self.node = Node(digest("test"), "127.0.0.1", 1234)
        self.router = RoutingTable(self, 20, self.node.id)

    def test_MarketProtocol_connect_multiplexer_correctly(self):
        mp = MarketProtocol(0, 0, 0, 0)
        self.assertEqual(mp.multiplexer, None)
        mp.connect_multiplexer("3")
        self.assertEqual(mp.multiplexer, "3")

    def test_MarketProtocol_add_listener_correctly(self):
        mp = MarketProtocol(0, 0, 0, 0)
        self.assertEqual(len(mp.listeners), 0)
        mp.add_listener(3)
        self.assertEqual(len(mp.listeners), 1)

    def test_MarketProtocol_rpc_get_image_invalid_image_hash(self):
        catcher = self.catcher
        mp = MarketProtocol(self.node, self.router, 0, 0)
        self.assertEqual(None, mp.rpc_get_image(mknode(), "invalid_hash"))
        catch_exception = catcher.pop()
        exception_message = catcher.pop()
        self.assertEquals(catch_exception["message"][0], "[WARNING] could not find image 696e76616c69645f68617368")
        self.assertEquals(exception_message["message"][0], "[WARNING] Image hash is not 20 characters invalid_hash")
