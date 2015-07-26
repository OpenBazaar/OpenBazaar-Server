__author__ = 'chris'

import json
import os.path
import nacl.signing

from twisted.internet import defer

from market.protocol import MarketProtocol

from dht.utils import digest, deferredDict

from collections import OrderedDict

from constants import DATA_FOLDER

from protos import objects

from binascii import hexlify

class Server(object):

    def __init__(self, kserver, signing_key):
        """
        A high level class for sending direct, market messages to other nodes.
        A node will need one of these to participate in buying and selling.
        Should be initialized after the Kademlia server.
        """
        self.kserver = kserver
        self.router = kserver.protocol.router
        self.protocol = MarketProtocol(kserver.node.getProto(), self.router, signing_key)

    def get_contract(self, node_to_ask, contract_hash):
        """
        Will query the given node to fetch a contract given its hash.
        If the returned contract doesn't have the same hash, it will return None.

        Args:
            node_to_ask: a `dht.node.Node` object containing an ip and port
            contract_hash: a 20 byte hash in raw byte format
        """
        def get_result(result):
            if digest(result[1][0]) == contract_hash:
                self.cache(result[1][0])
                return json.loads(result[1][0], object_pairs_hook=OrderedDict)
            else:
                return None
        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetContract(node_to_ask, contract_hash)
        return d.addCallback(get_result)

    def get_image(self, node_to_ask, image_hash):
        """
        Will query the given node to fetch an image given its hash.
        If the returned image doesn't have the same hash, it will return None.

        Args:
            node_to_ask: a `dht.node.Node` object containing an ip and port
            image_hash: a 20 byte hash in raw byte format
        """
        def get_result(result):
            if digest(result[1][0]) == image_hash:
                self.cache(result[1][0])
                return result[1][0]
            else:
                return None
        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetImage(node_to_ask, image_hash)
        return d.addCallback(get_result)

    def get_profile(self, node_to_ask):
        """
        Downloads the profile from the given node. If the images do not already
        exist in cache, it will download and cache them before returning the profile.
        """
        dl = []

        def get_result(result):
            def ret(result, profile):
                return profile
            try:
                pubkey = node_to_ask.signedPublicKey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                p = objects.Profile()
                p.ParseFromString(result[1][0])
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(p.avatar_hash)):
                    dl.append(self.get_image(node_to_ask, p.avatar_hash))
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(p.header_hash)):
                    dl.append(self.get_image(node_to_ask, p.header_hash))
                return defer.gatherResults(dl).addCallback(ret, p)
            except:
                return None
        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetProfile(node_to_ask)
        return d.addCallback(get_result)

    def cache(self, file):
        """
        Saves the file to a cache folder if it doesn't already exist.
        """
        if not os.path.exists(DATA_FOLDER + "cache"):
            os.makedirs(DATA_FOLDER + "cache")

        if not os.path.isfile(DATA_FOLDER + "cache/" + digest(file).encode("hex")):
            with open(DATA_FOLDER + "cache/" + digest(file).encode("hex"), 'w') as outfile:
                outfile.write(file)
