__author__ = 'chris'

import sys, os
from twisted.application import service, internet
from twisted.python.log import ILogObserver
from twisted.internet import reactor

from dht.utils import digest
from dht.network import Server
from dht import log, kprotocol
from dht.kprotocol import Node, Transport

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
    n = Node()
    n.guid = digest("guid")
    n.ip = "127.0.0.1"
    n.port = 1235
    n.transport = kprotocol.TCP
    kserver.set("socks", digest("contract"), n.SerializeToString())

def retrieve():
    d = kserver.get("socks")
    d.addCallback(printVal)

def printVal(value):
    print "Retrieved value:"
    n = Node()
    n.ParseFromString(value)
    print n

reactor.callLater(3, store)
reactor.callLater(5, retrieve)
