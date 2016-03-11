__author__ = 'ddustin'

from twisted.trial import unittest
from market.btcprice import BtcPrice

class MarketProtocolTest(unittest.TestCase):
    def test_BtcPrice(self):
        btcPrice = BtcPrice()
        btcPrice.start()
        rate = BtcPrice.instance().get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join(1)

    def test_BtcPrice_loadbitcoinaverage(self):
        btcPrice = BtcPrice()
        self.assertTrue(btcPrice.loadbitcoinaverage())
        self.assertGreater(btcPrice.get("USD"), 0)

    def test_BtcPrice_loadblockchain(self):
        btcPrice = BtcPrice()
        self.assertTrue(btcPrice.loadblockchain())
        self.assertGreater(btcPrice.get("USD"), 0)

    def test_BtcPrice_loadcoinkite(self):
        btcPrice = BtcPrice()
        self.assertTrue(btcPrice.loadcoinkite())
        self.assertGreater(btcPrice.get("USD"), 0)

    def test_BtcPrice_loadbitcoincharts(self):
        btcPrice = BtcPrice()
        self.assertTrue(btcPrice.loadbitcoincharts())
        self.assertGreater(btcPrice.get("USD"), 0)
