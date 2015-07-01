__author__ = 'chris'
"""
Just using this class for testing the DHT for now.
We will fit the actual implementation in where appropriate.
"""
import sys, os
import random
import pyelliptic

from twisted.application import service, internet
from twisted.python.log import ILogObserver
from twisted.internet import reactor

from binascii import unhexlify

from bitcoin import *

from dht.utils import digest
from dht.network import Server
from dht import log, kprotocol
from dht.node import Node

sys.path.append(os.path.dirname(__file__))

application = service.Application("openbazaar")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

#key generation for testing
priv = random_key()
pub = privkey_to_pubkey(priv)
pub_compressed = unhexlify(encode_pubkey(pub, "hex_compressed"))

pub_uncompressed = decode_pubkey(hexlify(pub_compressed), formt='hex_compressed')
pubkey_hex = encode_pubkey(pub_uncompressed, formt="hex")
pubkey_raw = changebase(pubkey_hex[2:],16,256,minlen=64)

privkey = encode_privkey(priv, "bin")
pubkey = '\x02\xca\x00 '+pubkey_raw[:32]+'\x00 '+pubkey_raw[32:]
alice = pyelliptic.ECC(curve='secp256k1', pubkey=pubkey, raw_privkey=privkey)

#kademlia
for i in range(0, 1):
    node = Node(digest(random.getrandbits(255)), ip="127.0.0.1", port=8466+i, pubkey=pub_compressed)
    kserver = Server(node)
    kserver.bootstrap([("127.0.0.1", 8467, pub_compressed)])
    server = internet.UDPServer(8466+i, kserver.protocol)
    server.setServiceParent(application)

def printIP():
    d = kserver.inetVisibleIP()
    d.addCallback(printVal)

def store():
    n = kprotocol.Node()
    n.guid = digest("guidc")
    n.ip = "127.0.0.1"
    n.port = 1235
    n.transport = kprotocol.TCP
    n.publicKey = pub_compressed
    kserver.set("shoes", digest("contract1"), n.SerializeToString())
    kserver.set("shoes", digest("contract2"), n.SerializeToString())

def delete():
    signature = alice.sign(digest("contract1"))
    kserver.delete("shoes", digest("contract1"), signature)

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
#reactor.callLater(7, delete)
#reactor.callLater(9, retrieve)

