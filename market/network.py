__author__ = 'chris'

import json
import os.path
import nacl.signing

from dht import node
from twisted.internet import defer
from market.protocol import MarketProtocol
from dht.utils import digest, deferredDict
from collections import OrderedDict
from constants import DATA_FOLDER
from protos import objects
from binascii import hexlify, unhexlify

class Server(object):

    def __init__(self, kserver, signing_key):
        """
        A high level class for sending direct, market messages to other nodes.
        A node will need one of these to participate in buying and selling.
        Should be initialized after the Kademlia server.
        """
        self.kserver = kserver
        self.signing_key = signing_key
        self.router = kserver.protocol.router
        self.protocol = MarketProtocol(kserver.node.getProto(), self.router, signing_key)

    def get_contract(self, node_to_ask, contract_hash):
        """
        Will query the given node to fetch a contract given its hash.
        If the returned contract doesn't have the same hash, it will return None.

        After acquiring the contract it will download all the associated images if it
        does not already have them in cache.

        Args:
            node_to_ask: a `dht.node.Node` object containing an ip and port
            contract_hash: a 20 byte hash in raw byte format
        """
        def get_result(result):
            if digest(result[1][0]) == contract_hash:
                contract = json.loads(result[1][0], object_pairs_hook=OrderedDict)
                try:
                    signature = contract["vendor"]["signatures"]["guid"]
                    pubkey = node_to_ask.signed_pubkey[64:]
                    verify_key = nacl.signing.VerifyKey(pubkey)
                    verify_key.verify(unhexlify(signature) + unhexlify(json.dumps(contract["vendor"]["listing"], indent=4).encode("hex")))
                except Exception:
                    return None
                self.cache(result[1][0])
                if "images" in contract["vendor"]["listing"]["item"]:
                    for image_hash in contract["vendor"]["listing"]["item"]["images"]["image_hashes"]:
                        self.get_image(node_to_ask, unhexlify(image_hash))
                return contract
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
        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                p = objects.Profile()
                p.ParseFromString(result[1][0])
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(p.avatar_hash)):
                    self.get_image(node_to_ask, p.avatar_hash)
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(p.header_hash)):
                    self.get_image(node_to_ask, p.header_hash)
                return p
            except:
                return None
        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetProfile(node_to_ask)
        return d.addCallback(get_result)

    def get_user_metadata(self, node_to_ask):
        """
        Downloads just a small portion of the profile (containing the name, handle,
        and avatar hash). We need this for some parts of the UI where we list stores.
        Since we need fast loading we shouldn't download the full profile here.
        It will download the avatar if it isn't already in cache.
        """
        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                m = objects.Metadata()
                m.ParseFromString(result[1][0])
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(m.avatar_hash)):
                    self.get_image(node_to_ask, m.avatar_hash)
                return m
            except:
                return None
        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetUserMetadata(node_to_ask)
        return d.addCallback(get_result)

    def get_listings(self, node_to_ask):
        """
        Queries a store for it's list of contracts. A `objects.Listings` protobuf
        is returned containing some metadata for each contract. The individual contracts
        should be fetched with a get_contract call.
        """
        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                l = objects.Listings()
                l.ParseFromString(result[1][0])
                return l
            except:
                return None
        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetListings(node_to_ask)
        return d.addCallback(get_result)

    def get_contract_metadata(self, node_to_ask, contract_hash):
        """
        Downloads just the metadata for the contract. Useful for displaying
        search results in a list view without downloading the entire contract.
        It will download the thumbnail image if it isn't already in cache.
        """
        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                l = objects.Listings().ListingMetadata()
                l.ParseFromString(result[1][0])
                if l.HasField("thumbnail_hash"):
                    if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(l.thumbnail_hash)):
                        self.get_image(node_to_ask, l.thumbnail_hash)
                return l
            except:
                return None
        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetContractMetadata(node_to_ask, contract_hash)
        return d.addCallback(get_result)

    def get_moderators(self):
        """
        Retrieves moderator list from the dht. Each node is queried
        to get metadata and ensure it's alive for usage.
        """
        def parse_response(moderators):
            if moderators is None:
                return None

            def parse_profiles(responses):
                for k, v in responses.items():
                    if v is None:
                        del responses[k]
                return responses
            ds = {}
            for mod in moderators:
                try:
                    val = objects.Value()
                    val.ParseFromString(mod)
                    n = objects.Node()
                    n.ParseFromString(val.serializedData)
                    ds[val.serializedData] = self.get_profile(node.Node(n.guid, n.ip, n.port, n.signedPublicKey))
                except:
                    pass
            return deferredDict(ds).addCallback(parse_profiles)
        return self.kserver.get("moderators").addCallback(parse_response)

    def make_moderator(self):
        proto = self.kserver.node.getProto().SerializeToString()
        self.kserver.set("moderators", digest(proto), proto)

    def unmake_moderator(self):
        key = digest(self.kserver.node.getProto().SerializeToString())
        signature = self.signing_key.Sign(key)[:64]
        self.kserver.delete("moderators", key, signature)

    def cache(self, file):
        """
        Saves the file to a cache folder if it doesn't already exist.
        """
        if not os.path.isfile(DATA_FOLDER + "cache/" + digest(file).encode("hex")):
            with open(DATA_FOLDER + "cache/" + digest(file).encode("hex"), 'w') as outfile:
                outfile.write(file)
