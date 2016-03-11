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
        btcPrice.join()

    @staticmethod
    def test_BtcPrice_loadFailures():
        for x in range(1, 5):
            btcPrice = BtcPrice()
            btcPrice.loadFailure = x
            btcPrice.start()
            btcPrice.closethread()
            btcPrice.join()

    def test_BtcPrice_loadbitcoinaverage(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadbitcoinaverage"]
        btcPrice.start()
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()

    def test_BtcPrice_loadblockchain(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadblockchain"]
        btcPrice.start()
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()

    def test_BtcPrice_loadcoinkite(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadcoinkite"]
        btcPrice.start()
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()

    def test_BtcPrice_loadbitcoincharts(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadbitcoincharts"]
        btcPrice.start()
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()
