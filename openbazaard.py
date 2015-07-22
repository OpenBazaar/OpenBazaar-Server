__author__ = 'chris'
"""
Just using this class for testing the DHT for now.
We will fit the actual implementation in where appropriate.
"""
import pickle
import stun
from twisted.internet import reactor
from twisted.python import log
from bitcoin import *
from txjsonrpc.netstring import jsonrpc
from guidutils.guid import GUID
from dht.utils import digest
from dht.network import Server
from dht.node import Node
from wireprotocol import OpenBazaarProtocol
from binascii import unhexlify
from constants import DATA_FOLDER
from market import network

log.startLogging(sys.stdout)

response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=0, stun_port=19302)
ip_address = response[1]
port = response[2]

# key generation for testing
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
mserver = network.Server(kserver)
mserver.protocol.connect_multiplexer(protocol)
protocol.register_processor(mserver.protocol)

reactor.listenUDP(18467, protocol)

# RPC-Server
class RPCCalls(jsonrpc.JSONRPC):
    def jsonrpc_getpubkey(self):
        return hexlify(g.signed_pubkey)

    def jsonrpc_getinfo(self):
        info = {"version": "0.1"}
        num_peers = 0
        for bucket in kserver.protocol.router.buckets:
            num_peers += bucket.__len__()
        info["known peers"] = num_peers
        info["stored messages"] = len(kserver.storage.data)
        size = sys.getsizeof(kserver.storage.data)
        size += sum(map(sys.getsizeof, kserver.storage.data.itervalues())) + sum(
            map(sys.getsizeof, kserver.storage.data.iterkeys()))
        info["db size"] = size
        return info

    def jsonrpc_set(self, keyword, key):
        def handle_result(result):
            print "JSONRPC result:", result

        d = kserver.set(str(keyword), digest(key), node.getProto().SerializeToString())
        d.addCallback(handle_result)
        return "Sending store request..."

    def jsonrpc_get(self, keyword):
        def handle_result(result):
            print "JSONRPC result:", result

        d = kserver.get(keyword)
        d.addCallback(handle_result)
        return "Sent get request. Check log output for result"

    def jsonrpc_delete(self, keyword, key):
        def handle_result(result):
            print "JSONRPC result:", result

        signature = g.signing_key.sign(digest(key))
        d = kserver.delete(str(keyword), digest(key), signature[:64])
        d.addCallback(handle_result)
        return "Sending delete request..."

    def jsonrpc_shutdown(self):
        for addr in kserver.protocol:
            connection = kserver.protocol._active_connections.get(addr)
            if connection is not None:
                connection.shutdown()
        return "Closing all connections."

    def jsonrpc_getpeers(self):
        peers = []
        for bucket in kserver.protocol.router.buckets:
            for node in bucket.getNodes():
                peers.append(node.id.encode("hex"))
        return peers

    def jsonrpc_getnode(self, guid):
        n = kserver.get_node(unhexlify(guid))
        return n

factory = jsonrpc.RPCFactory(RPCCalls)
factory.addIntrospection()
reactor.listenTCP(18465, factory, interface="127.0.0.1")

reactor.run()