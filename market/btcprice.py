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

            success = self.loadbitcoinaverage()

            if not success:
                success = self.loadblockchain()

            if not success:
                success = self.loadcoinkite()

            if not success:
                success = self.loadbitcoincharts()

            if not success:
                print "BtcPrice unable to load Bitcoin exchange price"

            now = datetime.now()
            sleepTime = timedelta(minutes=minuteInterval - now.minute % minuteInterval).total_seconds() - now.second

            self.condition.wait(sleepTime)
            self.condition.release()

        BtcPrice.__instance = None

    def loadbitcoinaverage(self):
        try:
            request = Request('https://api.bitcoinaverage.com/ticker/all')
            result = json.loads(urlopen(request).read())

            for currency, info in result.iteritems():
                if currency != "timestamp":
                    self.prices[currency] = info["last"]

            return True
        except URLError as e:
            print "Error loading bitcoinaverage url " + str(e)
        except (ValueError, KeyError, TypeError) as e:
            print "Error reading bitcoinaverage data" + str(e)

        return False

    def loadblockchain(self):
        try:
            request = Request('https://blockchain.info/ticker')
            result = json.loads(urlopen(request).read())

            for currency, info in result.iteritems():
                self.prices[currency] = info["last"]

            return True
        except URLError as e:
            print "Error loading bitcoinaverage url " + str(e)
        except (ValueError, KeyError, TypeError) as e:
            print "Error reading bitcoinaverage data" + str(e)

        return False

    def loadcoinkite(self):
        try:
            request = Request('https://api.coinkite.com/public/rates')
            result = json.loads(urlopen(request).read())

            for currency, info in result["rates"]["BTC"].iteritems():
                self.prices[currency] = info["rate"]

            return True
        except URLError as e:
            print "Error loading bitcoinaverage url " + str(e)
        except (ValueError, KeyError, TypeError) as e:
            print "Error reading bitcoinaverage data" + str(e)

        return False

    def loadbitcoincharts(self):
        try:
            request = Request('http://api.bitcoincharts.com/v1/weighted_prices.json')
            result = json.loads(urlopen(request).read())

            for currency, info in result.iteritems():
                if currency != "timestamp":
                    self.prices[currency] = info["24h"]

            return True
        except URLError as e:
            print "Error loading bitcoinaverage url " + str(e)
        except (ValueError, KeyError, TypeError) as e:
            print "Error reading bitcoinaverage data" + str(e)

        return False
