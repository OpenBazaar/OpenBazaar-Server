__author__ = 'chris'
"""
Just using this class for testing the DHT for now.
We will fit the actual implementation in where appropriate.
"""
import pickle
import stun
from twisted.internet import reactor
from twisted.python import log, logfile
from bitcoin import *
from guidutils.guid import GUID
from dht.network import Server
from dht.node import Node
from wireprotocol import OpenBazaarProtocol
from constants import DATA_FOLDER
from market import network
from txjsonrpc.netstring import jsonrpc
from networkcli import RPCCalls

# logging
logFile = logfile.LogFile.fromFullPath(DATA_FOLDER + "debug.log")
log.addObserver(log.FileLogObserver(logFile).emit)
log.startLogging(sys.stdout)

# stun
response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=0, stun_port=19302)
ip_address = response[1]
port = response[2]

# key generation
if os.path.isfile(DATA_FOLDER + 'keys.pickle'):
    keys = pickle.load(open(DATA_FOLDER + "keys.pickle", "r"))
    g = keys["guid"]
else:
    print "Generating GUID, stand by..."
    g = GUID()
    keys = {'guid': g}
    pickle.dump(keys, open(DATA_FOLDER + "keys.pickle", "wb"))

protocol = OpenBazaarProtocol((ip_address, port))

# kademlia
node = Node(g.guid, signed_pubkey=g.signed_pubkey)

if os.path.isfile(DATA_FOLDER + 'cache.pickle'):
    kserver = Server.loadState(DATA_FOLDER + 'cache.pickle', ip_address, port, protocol)
else :
    kserver = Server(node)
    kserver.protocol.connect_multiplexer(protocol)
    kserver.bootstrap(kserver.querySeed("162.213.253.147:8080", "909b4f614ec4fc8c63aab83b91bc620d7a238600bf256472e968fdafce200128"))

kserver.saveStateRegularly(DATA_FOLDER + 'cache.pickle', 10)
protocol.register_processor(kserver.protocol)

# market
mserver = network.Server(kserver, g.signing_key)
mserver.protocol.connect_multiplexer(protocol)
protocol.register_processor(mserver.protocol)

reactor.listenUDP(18467, protocol)

# json-rpc server
factory = jsonrpc.RPCFactory(RPCCalls(kserver, mserver))
reactor.listenTCP(18465, factory, interface="127.0.0.1")

reactor.run()