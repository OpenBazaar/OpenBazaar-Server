__author__ = 'chris'
import stun
import os
import sys
import dht.constants
from db.datastore import create_database
from twisted.internet import reactor
from twisted.python import log, logfile
from twisted.web.server import Site
from twisted.web.static import File
from keyutils.keys import KeyChain
from dht.network import Server
from dht.node import Node
from wireprotocol import OpenBazaarProtocol
from constants import DATA_FOLDER, DATABASE
from market import network
from market.listeners import MessageListenerImpl, NotificationListenerImpl
from ws import WSFactory, WSProtocol
from autobahn.twisted.websocket import listenWS
from restapi import OpenBazaarAPI
from dht.storage import PersistentStorage

# logging
logFile = logfile.LogFile.fromFullPath(DATA_FOLDER + "debug.log")
log.addObserver(log.FileLogObserver(logFile).emit)
log.startLogging(sys.stdout)

# stun
print "Finding NAT Type.."
response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=18467, stun_port=19302)
print "%s on %s:%s" % (response[0], response[1], response[2])
ip_address = response[1]
port = response[2]

# database
if not os.path.isfile(DATABASE):
    create_database()

# key generation
keys = KeyChain()

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
    kserver = Server.loadState(DATA_FOLDER + 'cache.pickle', ip_address, port, protocol,
                               on_bootstrap_complete, storage=PersistentStorage(DATABASE))
else:
    kserver = Server(node, dht.constants.KSIZE, dht.constants.ALPHA, storage=PersistentStorage(DATABASE))
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

# websockets api
ws_factory = WSFactory("ws://127.0.0.1:18466", mserver, kserver)
ws_factory.protocol = WSProtocol
ws_factory.setProtocolOptions(allowHixie76=True)
listenWS(ws_factory)
webdir = File(".")
web = Site(webdir)
reactor.listenTCP(9000, web, interface="127.0.0.1")

# rest api
api = OpenBazaarAPI(mserver, kserver, protocol)
site = Site(api, timeout=None)
reactor.listenTCP(18469, site, interface="127.0.0.1")

reactor.run()

