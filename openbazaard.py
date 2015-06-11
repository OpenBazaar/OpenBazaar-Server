__author__ = 'chris'

import sys, os
from twisted.application import service, internet
from twisted.python.log import ILogObserver
from twisted.internet import reactor

from dht.network import Server
from dht import log
sys.path.append(os.path.dirname(__file__))

application = service.Application("openbazaar")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

#kademlia
kserver = Server()
kserver.bootstrap([("127.0.0.1", 8469)])

server = internet.UDPServer(8468, kserver.protocol)
server.setServiceParent(application)

def printIP():
    d = kserver.inetVisibleIP()
    d.addCallback(printVal)

def store():
    kserver.set("hello", "world")

def retrieve():
    d = kserver.get("hello")
    d.addCallback(printVal)

def printVal(value):
    print "Retrieved value:", value

reactor.callLater(3, printIP)
#reactor.callLater(5, retrieve)
