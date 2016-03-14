__author__ = 'ddustin'

import time
from twisted.trial import unittest
from market.btcprice import BtcPrice

class MarketProtocolTest(unittest.TestCase):
    def test_BtcPrice(self):
        btcPrice = BtcPrice()
        btcPrice.start()
        time.sleep(0.01)
        rate = BtcPrice.instance().get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()

    @staticmethod
    def test_BtcPrice_load_failures():
        for x in range(1, 5):
            btcPrice = BtcPrice()
            btcPrice.loadFailure = x
            btcPrice.start()
            time.sleep(0.01)
            btcPrice.closethread()
            btcPrice.join()

    def test_BtcPrice_loadbitcoinaverage(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadbitcoinaverage"]
        btcPrice.start()
        time.sleep(0.01)
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()

    def test_BtcPrice_loadblockchain(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadblockchain"]
        btcPrice.start()
        time.sleep(0.01)
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()

    def test_BtcPrice_loadcoinkite(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadcoinkite"]
        btcPrice.start()
        time.sleep(0.01)
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()

    def test_BtcPrice_loadbitcoincharts(self):
        btcPrice = BtcPrice()
        btcPrice.loadPriorities = ["loadbitcoincharts"]
        btcPrice.start()
        time.sleep(0.01)
        rate = btcPrice.get("USD")
        self.assertGreater(rate, 0)
        btcPrice.closethread()
        btcPrice.join()
