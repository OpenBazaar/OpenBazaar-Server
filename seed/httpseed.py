__author__ = 'chris'
import sys, os
import gzip
import pickle
import stun
import json
import random

import nacl.signing, nacl.hash, nacl.encoding

from cStringIO import StringIO

from twisted.application import service, internet
from twisted.python.log import ILogObserver
from twisted.internet import task
from twisted.web import resource, server

from binascii import unhexlify, hexlify

from random import shuffle

from seed import peers

from guid import guid

from dht import log
from dht.node import Node
from dht.network import Server
from dht.crawling import NodeSpiderCrawl
from dht.utils import digest, deferredDict
from dht import kprotocol

sys.path.append(os.path.dirname(__file__))
application = service.Application("OpenBazaar_seed_server")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

# Load the keys
if os.path.isfile('keys.pickle'):
    keys = pickle.load(open("keys.pickle", "r"))
    privkey = keys["kademlia_key"]
    signing_key_hex = keys["signing_privkey"]
    signing_key = nacl.signing.SigningKey(signing_key_hex, encoder=nacl.encoding.HexEncoder)
else:
    print "Generating GUID, stand by..."
    privkey = hexlify(guid.generate())
    signing_key = nacl.signing.SigningKey.generate()
    keys = {
            'kademlia_key': privkey,
            'signing_privkey': signing_key.encode(encoder=nacl.encoding.HexEncoder),
            'signing_pubkey': signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
            }
    pickle.dump(keys, open("keys.pickle", "wb"))

# Create the guid
privkey = nacl.signing.SigningKey(privkey, encoder=nacl.encoding.HexEncoder)
pubkey = privkey.verify_key
signed_pubkey = privkey.sign(str(pubkey))
h = nacl.hash.sha512(signed_pubkey)
guid = unhexlify(h[:40])

# Stun
response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=0, stun_port=19302)
ip_address = response[1]
port = 18467

# Start the kademlia server
this_node = Node(guid, ip_address, port, signed_pubkey)

if os.path.isfile('cache.pickle'):
    kserver = Server.loadState('cache.pickle', ip_address, port)
else:
    kserver = Server(this_node)

kserver.saveStateRegularly('cache.pickle', 10)
udpserver = internet.UDPServer(18467, kserver.protocol)
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
                n = kprotocol.Node()
                n.ParseFromString(proto)
                if n.merchant:
                    node = Node(n.guid, n.ip, n.port, n.signedPublicKey, n.merchant, n.server_port, n.transport)
                else:
                    node = Node(n.guid, n.ip, n.port, n.signedPublicKey)
                if node.id not in self.nodes:
                    self.nodes[node.id] = node
            shuffle(self.nodes)

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
                if node not in self.nodes:
                    self.nodes[node.id] = node
        for node in self.nodes.values():
            if node.id != this_node.id:
                ds[node] = self.kserver.protocol.callPing(node)
        deferredDict(ds).addCallback(start_crawl)

    def getChild(self, child, request):
        return self

    def render_GET(self, request):
        print request.args
        log.msg("Received a request for nodes, responding...")
        if "format" in request.args:
            if request.args["format"][0] == "json":
                json_list = []
                if "type" in request.args and request.args["type"][0] == "vendors":
                    print "getting list of vendors"
                    for node in self.nodes.values():
                        if node.merchant is True:
                            print "found vendor"
                            node_dic = {}
                            node_dic["ip"] = node.ip
                            node_dic["port"] = node.port
                            json_list.append(node_dic)
                    sig = signing_key.sign(str(json_list))
                    resp = {"peers" : json_list, "signature" : hexlify(sig[:64])}
                    request.write(json.dumps(resp, indent=4))
                else:
                    for node in self.nodes.values()[:50]:
                        node_dic = {}
                        node_dic["ip"] = node.ip
                        node_dic["port"] = node.port
                        json_list.append(node_dic)
                    sig = signing_key.sign(str(json_list))
                    resp = {"peers" : json_list, "signature" : hexlify(sig[:64])}
                    request.write(json.dumps(resp, indent=4))
            elif request.args["format"][0] == "protobuf":
                proto = peers.PeerSeeds()
                for node in self.nodes.values()[:50]:
                    peer = peers.PeerData()
                    peer.ip_address = node.ip
                    peer.port = node.port
                    peer.vendor = node.merchant
                    proto.peer_data.append(peer.SerializeToString())

                sig = signing_key.sign("".join(proto.peer_data))
                proto.signature = sig
                uncompressed_data = proto.SerializeToString()
                buf = StringIO()
                f = gzip.GzipFile(mode='wb', fileobj=buf)
                try:
                    f.write(uncompressed_data)
                finally:
                    f.close()
                resp = buf.getvalue()
                request.write(resp)
        else:
            proto = peers.PeerSeeds()
            if "type" in request.args and request.args["type"][0] == "vendors":
                for node in self.nodes.values():
                    if node.merchant is True:
                        peer = peers.PeerData()
                        peer.ip_address = node.ip
                        peer.port = node.port
                        peer.vendor = node.merchant
                        proto.peer_data.append(peer.SerializeToString())

                sig = signing_key.sign("".join(proto.peer_data))
                proto.signature = sig
                uncompressed_data = proto.SerializeToString()
                buf = StringIO()
                f = gzip.GzipFile(mode='wb', fileobj=buf)
                try:
                    f.write(uncompressed_data)
                finally:
                    f.close()
                resp = buf.getvalue()
                request.write(resp)
            else:
                for node in self.nodes.values()[:50]:
                    peer = peers.PeerData()
                    peer.ip_address = node.ip
                    peer.port = node.port
                    peer.vendor = node.merchant
                    proto.peer_data.append(peer.SerializeToString())

                sig = signing_key.sign("".join(proto.peer_data))
                proto.signature = sig
                uncompressed_data = proto.SerializeToString()
                buf = StringIO()
                f = gzip.GzipFile(mode='wb', fileobj=buf)
                try:
                    f.write(uncompressed_data)
                finally:
                    f.close()
                resp = buf.getvalue()
                request.write(resp)
        request.finish()
        return server.NOT_DONE_YET

server_protocol = server.Site(WebResource(kserver))
seed_server = internet.TCPServer(8080, server_protocol)
seed_server.setServiceParent(application)