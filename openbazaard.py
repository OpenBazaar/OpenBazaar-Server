__author__ = 'chris'
"""
Just using this class for testing the DHT for now.
We will fit the actual implementation in where appropriate.
"""
import pickle
from twisted.application import service, internet
from twisted.python.log import ILogObserver
from binascii import hexlify
from os.path import expanduser

import stun
from bitcoin import *
from txjsonrpc.netstring import jsonrpc

from guidutils.guid import GUID
from dht.utils import digest
from dht.network import Server
import log
from dht.node import Node
from wireprotocol import OpenBazaarProtocol

datafolder = expanduser("~") + "/OpenBazaar/"
if not os.path.exists(datafolder):
    os.makedirs(datafolder)

def get_data_folder():
    return datafolder

response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=0, stun_port=19302)
ip_address = response[1]
port = response[2]

application = service.Application("openbazaar")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

# key generation for testing
if os.path.isfile(datafolder + 'keys.pickle'):
    keys = pickle.load(open(datafolder + "keys.pickle", "r"))
    g = keys["guid"]
else:
    print "Generating GUID, stand by..."
    g = GUID()
    keys = {'guid': g}
    pickle.dump(keys, open(datafolder + "keys.pickle", "wb"))

protocol = OpenBazaarProtocol((ip_address, port))

# kademlia
node = Node(g.guid, signed_pubkey=g.signed_pubkey)

if os.path.isfile(datafolder + 'cache.pickle'):
    kserver = Server.loadState(datafolder + 'cache.pickle', ip_address, port, protocol)
else :
    kserver = Server(node)
    kserver.protocol.connect_multiplexer(protocol)
    kserver.bootstrap(kserver.querySeed("162.213.253.147:8080", "909b4f614ec4fc8c63aab83b91bc620d7a238600bf256472e968fdafce200128"))

kserver.saveStateRegularly(datafolder + 'cache.pickle', 10)
protocol.register_processor(kserver.protocol)
server = internet.UDPServer(18467, protocol)
server.setServiceParent(application)


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


factory = jsonrpc.RPCFactory(RPCCalls)
factory.addIntrospection()
jsonrpcServer = internet.TCPServer(18465, factory, interface="127.0.0.1")
jsonrpcServer.setServiceParent(application)
