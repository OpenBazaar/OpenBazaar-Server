__author__ = 'chris'
import sys
import pickle
import json
import random
import argparse
import platform
from binascii import hexlify
from random import shuffle
import os

from twisted.internet import task, reactor
from twisted.web import resource, server
import stun
import nacl.signing
import nacl.hash
import nacl.encoding
from twisted.python import log, logfile

from daemon import Daemon
from seed import peers
from dht.node import Node
from dht.network import Server
from dht.crawling import NodeSpiderCrawl
from dht.utils import digest, deferredDict
from protos import objects
from net.wireprotocol import OpenBazaarProtocol
from market import network
from keyutils.keys import KeyChain
from db.datastore import Database
from constants import DATA_FOLDER
from log import Logger, FileLogObserver


def run(*args):
    TESTNET = args[0]

    # Create the database
    db = Database(testnet=TESTNET)

    # logging
    logFile = logfile.LogFile.fromFullPath(DATA_FOLDER + "debug.log", rotateLength=15000000, maxRotatedFiles=1)
    log.addObserver(FileLogObserver(logFile, level="debug").emit)
    log.addObserver(FileLogObserver(level="debug").emit)
    logger = Logger(system="Httpseed")

    # Load the keys
    keychain = KeyChain(db)

    if os.path.isfile(DATA_FOLDER + 'keys.pickle'):
        keys = pickle.load(open(DATA_FOLDER + "keys.pickle", "r"))
        signing_key_hex = keys["signing_privkey"]
        signing_key = nacl.signing.SigningKey(signing_key_hex, encoder=nacl.encoding.HexEncoder)
    else:
        signing_key = nacl.signing.SigningKey.generate()
        keys = {
            'signing_privkey': signing_key.encode(encoder=nacl.encoding.HexEncoder),
            'signing_pubkey': signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        }
        pickle.dump(keys, open(DATA_FOLDER + "keys.pickle", "wb"))

    # Stun
    port = 18467 if not TESTNET else 28467
    logger.info("Finding NAT Type...")
    response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=port, stun_port=19302)
    logger.info("%s on %s:%s" % (response[0], response[1], response[2]))
    ip_address = response[1]
    port = response[2]

    # Start the kademlia server
    this_node = Node(keychain.guid, ip_address, port, keychain.guid_signed_pubkey, vendor=False)
    protocol = OpenBazaarProtocol((ip_address, port), response[0], testnet=TESTNET)

    try:
        kserver = Server.loadState('cache.pickle', ip_address, port, protocol, db)
    except Exception:
        kserver = Server(this_node, db)
        kserver.protocol.connect_multiplexer(protocol)

    protocol.register_processor(kserver.protocol)
    kserver.saveStateRegularly('cache.pickle', 10)

    # start the market server
    mserver = network.Server(kserver, keychain.signing_key, db)
    mserver.protocol.connect_multiplexer(protocol)
    protocol.register_processor(mserver.protocol)

    reactor.listenUDP(port, protocol)

    class WebResource(resource.Resource):
        def __init__(self, kserver_r):
            resource.Resource.__init__(self)
            self.kserver = kserver_r
            self.nodes = {}
            for bucket in self.kserver.protocol.router.buckets:
                for node in bucket.getNodes():
                    self.nodes[(node.ip, node.port)] = node
            self.nodes[(this_node.ip, this_node.port)] = this_node
            loopingCall = task.LoopingCall(self.crawl)
            loopingCall.start(60, True)

        def crawl(self):
            def gather_results(result):
                for proto in result:
                    n = objects.Node()
                    try:
                        n.ParseFromString(proto)
                        node = Node(n.guid, n.ip, n.port, n.signedPublicKey, n.vendor)
                        self.nodes[(node.ip, node.port)] = node
                    except Exception:
                        pass

            def start_crawl(results):
                for node, result in results.items():
                    if not result[0]:
                        del self.nodes[(node.ip, node.port)]
                node = Node(digest(random.getrandbits(255)))
                nearest = self.kserver.protocol.router.findNeighbors(node)
                spider = NodeSpiderCrawl(self.kserver.protocol, node, nearest, 100, 4)
                spider.find().addCallback(gather_results)

            ds = {}
            for bucket in self.kserver.protocol.router.buckets:
                for node in bucket.getNodes():
                    self.nodes[(node.ip, node.port)] = node
            for node in self.nodes.values():
                if node.id != this_node.id:
                    ds[node] = self.kserver.protocol.callPing(node)
            deferredDict(ds).addCallback(start_crawl)

        def getChild(self, child, request):
            return self

        def render_GET(self, request):
            nodes = self.nodes.values()
            shuffle(nodes)
            logger.info("Received a request for nodes, responding...")
            if "format" in request.args:
                if request.args["format"][0] == "json":
                    json_list = []
                    if "type" in request.args and request.args["type"][0] == "vendors":
                        for node in nodes:
                            if node.vendor is True:
                                node_dic = {}
                                node_dic["ip"] = node.ip
                                node_dic["port"] = node.port
                                json_list.append(node_dic)
                        sig = signing_key.sign(str(json_list))
                        resp = {"peers": json_list, "signature": hexlify(sig[:64])}
                        request.write(json.dumps(resp, indent=4))
                    else:
                        for node in nodes[:50]:
                            node_dic = {}
                            node_dic["ip"] = node.ip
                            node_dic["port"] = node.port
                            json_list.append(node_dic)
                        sig = signing_key.sign(str(json_list))
                        resp = {"peers": json_list, "signature": hexlify(sig[:64])}
                        request.write(json.dumps(resp, indent=4))
                elif request.args["format"][0] == "protobuf":
                    proto = peers.PeerSeeds()
                    for node in nodes[:50]:
                        peer = peers.PeerData()
                        peer.ip_address = node.ip
                        peer.port = node.port
                        peer.vendor = node.vendor
                        proto.peer_data.append(peer.SerializeToString())

                    sig = signing_key.sign("".join(proto.peer_data))[:64]
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

                    sig = signing_key.sign("".join(proto.peer_data))[:64]
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

                    sig = signing_key.sign("".join(proto.peer_data))[:64]
                    proto.signature = sig
                    uncompressed_data = proto.SerializeToString()
                    request.write(uncompressed_data.encode("zlib"))
            request.finish()
            return server.NOT_DONE_YET

    server_protocol = server.Site(WebResource(kserver))
    reactor.listenTCP(8080, server_protocol)

    reactor.run()

if __name__ == "__main__":
    # pylint: disable=anomalous-backslash-in-string
    class OpenBazaard(Daemon):
        def run(self, *args):
            run(*args)

    class Parser(object):
        def __init__(self, daemon):
            self.daemon = daemon
            parser = argparse.ArgumentParser(
                description='OpenBazaard Seed Server v0.1',
                usage='''
    python httpseed.py <command> [<args>]
    python httpseed.py <command> --help

commands:
    start            start the seed server
    stop             shutdown the server and disconnect
    restart          restart the server
''')
            parser.add_argument('command', help='Execute the given command')
            args = parser.parse_args(sys.argv[1:2])
            if not hasattr(self, args.command):
                parser.print_help()
                exit(1)
            getattr(self, args.command)()

        def start(self):
            parser = argparse.ArgumentParser(
                description="Start the seed server",
                usage='''usage:
        python openbazaard.py start [-d DAEMON]''')
            parser.add_argument('-d', '--daemon', action='store_true', help="run the server in the background")
            parser.add_argument('-t', '--testnet', action='store_true', help="use the test network")
            args = parser.parse_args(sys.argv[2:])
            print "OpenBazaar Seed Server v0.1 starting..."
            unix = ("linux", "linux2", "darwin")
            if args.daemon and platform.system().lower() in unix:
                self.daemon.start(args.testnet)
            else:
                run(args.testnet)

        def stop(self):
            # pylint: disable=W0612
            parser = argparse.ArgumentParser(
                description="Shutdown the server and disconnect",
                usage='''usage:
        python openbazaard.py stop''')
            print "OpenBazaar Seed Server stopping..."
            self.daemon.stop()

        def restart(self):
            # pylint: disable=W0612
            parser = argparse.ArgumentParser(
                description="Restart the server",
                usage='''usage:
        python openbazaard.py restart''')
            print "Restarting OpenBazaar server..."
            self.daemon.restart()

    Parser(OpenBazaard('/tmp/httpseed.pid'))
