__author__ = 'ddustin'

import json
from threading import Thread, Condition
from urllib2 import Request, urlopen, URLError
from datetime import datetime, timedelta

class BtcPrice(Thread):
    """
    A class for loading and caching the current Bitcoin exchange price.
    There only needs to be one instance of the class running, use BtcPrice.instance() to access it
    """

    @staticmethod
    def instance():
        return BtcPrice.__instance

    def __init__(self):
        Thread.__init__(self, name="BtcPrice Thread")
        self.prices = {}
        self.condition = Condition()
        self.keepRunning = True
        self.loadPriorities = ["loadbitcoinaverage", "loadblockchain", "loadcoinkite", "loadbitcoincharts"]
        self.loadFailure = 0
        BtcPrice.__instance = self

    def closethread(self):
        self.condition.acquire()
        self.keepRunning = False
        self.condition.notify()
        self.condition.release()

    def get(self, currency):
        """
        :param currency: an upper case 3 letter currency code
        :return: a floating point number representing the exchange rate from BTC => currency
        """
        self.loadPrices()
        self.condition.acquire()
        try:
            last = self.prices[currency]
        finally:
            self.condition.release()
        return last

    def run(self):
        minuteInterval = 15

        while self.keepRunning:

            self.condition.acquire()
            self.loadPrices()

            now = datetime.now()
            sleepTime = timedelta(minutes=minuteInterval - now.minute % minuteInterval).total_seconds() - now.second

            self.condition.wait(sleepTime)
            self.condition.release()

        BtcPrice.__instance = None

    def loadPrices(self):
        success = False
        for priority in self.loadPriorities:
            try:
                getattr(self, priority)()

                success = True
                break

            except URLError as e:
                if self.loadFailure == 0:  # pragma: no cover
                    print "Error loading " + priority + " url " + str(e)
            except (ValueError, KeyError, TypeError) as e:
                if self.loadFailure == 0:  # pragma: no cover
                    print "Error reading " + priority + " data" + str(e)

        if not success and self.loadFailure == 0:  # pragma: no cover
            print "BtcPrice unable to load Bitcoin exchange price"

    def dictForUrl(self, url):
        if self.loadFailure == 0:
            request = Request(url)
            result = urlopen(request).read()
        if self.loadFailure == 1:
            url = 'http://google.com/404'
            request = Request(url)
            result = urlopen(request).read()
        if self.loadFailure == 2:
            result = None
        if self.loadFailure == 3:
            result = ""
        if self.loadFailure == 4:
            result = '{"a":}'
        return json.loads(result)

    def loadbitcoinaverage(self):
        for currency, info in self.dictForUrl('https://api.bitcoinaverage.com/ticker/all').iteritems():
            if currency != "timestamp":
                self.prices[currency] = info["last"]

    def loadblockchain(self):
        for currency, info in self.dictForUrl('https://blockchain.info/ticker').iteritems():
            self.prices[currency] = info["last"]

    def loadcoinkite(self):
        for currency, info in self.dictForUrl('https://api.coinkite.com/public/rates')["rates"]["BTC"].iteritems():
            self.prices[currency] = info["rate"]

    def loadbitcoincharts(self):
        for currency, info in self.dictForUrl('https://api.bitcoincharts.com/v1/weighted_prices.json').iteritems():
            if currency != "timestamp":
                self.prices[currency] = info["24h"]
