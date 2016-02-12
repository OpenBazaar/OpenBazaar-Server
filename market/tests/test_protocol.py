from twisted.trial import unittest

from market.protocol import MarketProtocol

class MarketProtocolTest(unittest.TestCase):
    def test_connect_multiplexer(self):
        mp = MarketProtocol(0, 0, 0, 0)
        self.assertEqual(mp.multiplexer, None)
	mp.connect_multiplexer("3")
	self.assertEqual(mp.multiplexer, "3")

    def test_add_listener(self):
        mp = MarketProtocol(0, 0, 0, 0)
        self.assertEqual(len(mp.listeners), 0)
	mp.add_listener(3)
	self.assertEqual(len(mp.listeners),1)
