__author__ = 'chris'
"""
Just using this class for testing the DHT for now.
We will fit the actual implementation in where appropriate.
"""

import stun
import os
import sys
import dht.constants
from twisted.internet import reactor
from twisted.python import log, logfile
from twisted.web.server import Site
from twisted.web.static import File
from keyutils.keys import KeyChain
from dht.network import Server
from dht.node import Node
from wireprotocol import OpenBazaarProtocol
from constants import DATA_FOLDER
from txjsonrpc.netstring import jsonrpc
from networkcli import RPCCalls
from market import network
from market.listeners import MessageListenerImpl, NotificationListenerImpl
from ws import WSFactory, WSProtocol
from autobahn.twisted.websocket import listenWS

# logging
logFile = logfile.LogFile.fromFullPath(DATA_FOLDER + "debug.log")
log.addObserver(log.FileLogObserver(logFile).emit)
log.startLogging(sys.stdout)

# stun
print "Finding NAT Type.."
response = stun.get_ip_info(stun_host='seed.openbazaar.org', stun_port=3478, source_port=0)
print "%s on %s:%s" % (response[0], response[1], response[2])
ip_address = response[1]
port = response[2]

# key generation
keys = KeyChain()
print keys.guid.encode("hex")
print keys.encryption_pubkey.encode("hex")

def on_bootstrap_complete(resp):
    mlistener = MessageListenerImpl(ws_factory)
    mserver.get_messages(mlistener)
    mserver.protocol.add_listener(mlistener)
    nlistener = NotificationListenerImpl(ws_factory)
    mserver.protocol.add_listener(nlistener)

protocol = OpenBazaarProtocol((ip_address, port))

# kademlia
node = Node(keys.guid, ip_address, port, signed_pubkey=keys.guid_signed_pubkey)

if os.path.isfile(DATA_FOLDER + 'cache.pickle'):
    kserver = Server.loadState(DATA_FOLDER + 'cache.pickle', ip_address, port, protocol, on_bootstrap_complete)
else:
    kserver = Server(node, dht.constants.KSIZE, dht.constants.ALPHA)
    kserver.protocol.connect_multiplexer(protocol)
    kserver.bootstrap(
        kserver.querySeed("162.213.253.147:8080",
                          "5b56c8daeb3b37c8a9b47be6102fa43b9f069f58dcb57475984041b26c99e389"))\
        .addCallback(on_bootstrap_complete)

kserver.saveStateRegularly(DATA_FOLDER + 'cache.pickle', 10)
protocol.register_processor(kserver.protocol)

# market
mserver = network.Server(kserver, keys.signing_key)
mserver.protocol.connect_multiplexer(protocol)
protocol.register_processor(mserver.protocol)

reactor.listenUDP(port, protocol)

# json-rpc server
factory = jsonrpc.RPCFactory(RPCCalls(kserver, mserver, keys))
reactor.listenTCP(18465, factory, interface="127.0.0.1")

# web sockets
ws_factory = WSFactory("ws://127.0.0.1:18466", mserver)
ws_factory.protocol = WSProtocol
ws_factory.setProtocolOptions(allowHixie76=True)
listenWS(ws_factory)
webdir = File(".")
web = Site(webdir)
reactor.listenTCP(9000, web)

reactor.run()
