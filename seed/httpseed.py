__author__ = 'chris'
import sys
import os
import pickle
import json
import random
from twisted.application import service, internet
from twisted.python.log import ILogObserver
from twisted.internet import task
from twisted.web import resource, server
from binascii import hexlify
from random import shuffle

import stun
import nacl.signing
import nacl.hash
import nacl.encoding

from seed import peers
from guidutils.guid import GUID
import log
from dht.node import Node
from dht.network import Server
from dht.crawling import NodeSpiderCrawl
from dht.utils import digest, deferredDict

from protos import objects
from wireprotocol import OpenBazaarProtocol
from market import network

sys.path.append(os.path.dirname(__file__))
application = service.Application("OpenBazaar_seed_server")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

# Load the keys
if os.path.isfile('keys.pickle'):
    keys = pickle.load(open("keys.pickle", "r"))
    g = keys["guid"]
    signing_key_hex = keys["signing_privkey"]
    signing_key = nacl.signing.SigningKey(signing_key_hex, encoder=nacl.encoding.HexEncoder)
else:
    print "Generating GUID, stand by..."
    g = GUID()
    signing_key = nacl.signing.SigningKey.generate()
    keys = {
            'guid': g,
            'signing_privkey': signing_key.encode(encoder=nacl.encoding.HexEncoder),
            'signing_pubkey': signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
            }
    pickle.dump(keys, open("keys.pickle", "wb"))

# Stun
response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=0, stun_port=19302)
ip_address = response[1]
port = 18467

# Start the kademlia server
this_node = Node(g.guid, ip_address, port, g.signed_pubkey)
protocol = OpenBazaarProtocol((ip_address, port))

if os.path.isfile('cache.pickle'):
    kserver = Server.loadState('cache.pickle', ip_address, port, protocol)
else:
    kserver = Server(this_node)
    kserver.protocol.connect_multiplexer(protocol)

protocol.register_processor(kserver.protocol)
kserver.saveStateRegularly('cache.pickle', 10)

# start the market server
mserver = network.Server(kserver)
mserver.protocol.connect_multiplexer(protocol)
protocol.register_processor(mserver.protocol)

udpserver = internet.UDPServer(18467, protocol)
udpserver.setServiceParent(application)

class WebResource(resource.Resource):
    def __init__(self, kserver):
        resource.Resource.__init__(self)
        self.kserver = kserver
        self.nodes = {}
        for bucket in self.kserver.protocol.router.buckets:
            for node in bucket.getNodes():
                self.nodes[node.id] = node
        self.nodes[this_node.id] = this_node
        loopingCall = task.LoopingCall(self.crawl)
        loopingCall.start(60, True)

    def crawl(self):
        def gather_results(result):
            for proto in result:
                n = objects.Node()
                try:
                    n.ParseFromString(proto)
                    node = Node(n.guid, n.ip, n.port, n.signedPublicKey, n.vendor)
                    if node.id not in self.nodes:
                        self.nodes[node.id] = node
                except Exception:
                    pass

        def start_crawl(results):
            for node, result in results.items():
                if not result[0]:
                    del self.nodes[node.id]
            node = Node(digest(random.getrandbits(255)))
            nearest = self.kserver.protocol.router.findNeighbors(node)
            spider = NodeSpiderCrawl(self.kserver.protocol, node, nearest, 100, 4)
            d = spider.find().addCallback(gather_results)

        ds = {}
        for bucket in self.kserver.protocol.router.buckets:
            for node in bucket.getNodes():
                if node.id not in self.nodes:
                    self.nodes[node.id] = node
        for node in self.nodes.values():
            if node.id != this_node.id:
                ds[node] = self.kserver.protocol.callPing(node)
        deferredDict(ds).addCallback(start_crawl)

    def getChild(self, child, request):
        return self

    def render_GET(self, request):
        nodes = self.nodes.values()
        shuffle(nodes)
        log.msg("Received a request for nodes, responding...")
        if "format" in request.args:
            if request.args["format"][0] == "json":
                json_list = []
                if "type" in request.args and request.args["type"][0] == "vendors":
                    print "getting list of vendors"
                    for node in nodes:
                        if node.vendor is True:
                            print "found vendor"
                            node_dic = {}
                            node_dic["ip"] = node.ip
                            node_dic["port"] = node.port
                            json_list.append(node_dic)
                    sig = signing_key.sign(str(json_list))
                    resp = {"peers" : json_list, "signature" : hexlify(sig[:64])}
                    request.write(json.dumps(resp, indent=4))
                else:
                    for node in nodes[:50]:
                        node_dic = {}
                        node_dic["ip"] = node.ip
                        node_dic["port"] = node.port
                        json_list.append(node_dic)
                    sig = signing_key.sign(str(json_list))
                    resp = {"peers" : json_list, "signature" : hexlify(sig[:64])}
                    request.write(json.dumps(resp, indent=4))
            elif request.args["format"][0] == "protobuf":
                proto = peers.PeerSeeds()
                for node in nodes[:50]:
                    peer = peers.PeerData()
                    peer.ip_address = node.ip
                    peer.port = node.port
                    peer.vendor = node.vendor
                    proto.peer_data.append(peer.SerializeToString())

                sig = signing_key.sign("".join(proto.peer_data))
                proto.signature = sig
                uncompressed_data = proto.SerializeToString()
                request.write(uncompressed_data.encode("zlib"))
        else:
            proto = peers.PeerSeeds()
            if "type" in request.args and request.args["type"][0] == "vendors":
                for node in nodes:
                    if node.vendor is True:
                        peer = peers.PeerData()
                        peer.ip_address = node.ip
                        peer.port = node.port
                        peer.vendor = node.vendor
                        proto.peer_data.append(peer.SerializeToString())

                sig = signing_key.sign("".join(proto.peer_data))
                proto.signature = sig
                uncompressed_data = proto.SerializeToString()
                request.write(uncompressed_data.encode("zlib"))
            else:
                for node in nodes[:50]:
                    peer = peers.PeerData()
                    peer.ip_address = node.ip
                    peer.port = node.port
                    peer.vendor = node.vendor
                    proto.peer_data.append(peer.SerializeToString())

                sig = signing_key.sign("".join(proto.peer_data))
                proto.signature = sig
                uncompressed_data = proto.SerializeToString()
                request.write(uncompressed_data.encode("zlib"))
        request.finish()
        return server.NOT_DONE_YET

server_protocol = server.Site(WebResource(kserver))
seed_server = internet.TCPServer(8080, server_protocol)
seed_server.setServiceParent(application)
