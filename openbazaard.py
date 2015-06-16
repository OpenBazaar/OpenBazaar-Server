__author__ = 'chris'
"""
Just using this class for testing the DHT for now.
We will fit the actual implementation in where appropriate.
"""
import sys, os
import random

from twisted.application import service, internet
from twisted.python.log import ILogObserver
from twisted.internet import reactor

from binascii import unhexlify

from bitcoin import *

from dht.utils import digest
from dht.network import Server
from dht import log, kprotocol
from dht import kprotocol
from dht.node import Node

sys.path.append(os.path.dirname(__file__))

application = service.Application("openbazaar")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

#kademlia
for i in range(0, 1):
    node = Node(digest(random.getrandbits(255)),
                pubkey=unhexlify(encode_pubkey(privkey_to_pubkey(random_key()), "hex_compressed")))
    kserver = Server(node)
    kserver.bootstrap([("127.0.0.1", 8468)])
    server = internet.UDPServer(8470+i, kserver.protocol)
    server.setServiceParent(application)

def printIP():
    d = kserver.inetVisibleIP()
    d.addCallback(printVal)

def store():
    n = kprotocol.Node()
    n.guid = digest("guid")
    n.ip = "127.0.0.1"
    n.port = 1235
    n.transport = kprotocol.TCP
    kserver.set("shoes", digest("contract"), n.SerializeToString())
    kserver.set("shoes", digest("s"), n.SerializeToString())

def retrieve():
    d = kserver.get("shoes")
    d.addCallback(printVal)

def printVal(value):
    print "Retrieved value:"
    for v in value:
        val = kprotocol.Value()
        val.ParseFromString(v)
        print val
        node = kprotocol.Node()
        node.ParseFromString(val.serializedNode)
        print node

#reactor.callLater(3, store)
#reactor.callLater(5, retrieve)
