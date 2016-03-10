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

            try:
                request = Request('https://api.bitcoinaverage.com/ticker/all')
                result = json.loads(urlopen(request).read())

                for currency, info in result.iteritems():
                    if currency != "timestamp":
                        self.prices[currency] = info["last"]

            except URLError as e:
                print "Error loading bitcoinaverage url " + str(e)
            except (ValueError, KeyError, TypeError) as e:
                print "Error reading bitcoinaverage data" + str(e)

            now = datetime.now()
            sleepTime = timedelta(minutes=minuteInterval - now.minute % minuteInterval).total_seconds() - now.second

            self.condition.wait(sleepTime)
            self.condition.release()

        BtcPrice.__instance = None
