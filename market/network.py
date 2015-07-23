__author__ = 'chris'

import json
import os.path

from twisted.internet import defer

from market.protocol import MarketProtocol

from dht.utils import digest

from collections import OrderedDict

from constants import DATA_FOLDER

class Server(object):

    def __init__(self, kserver):
        """
        A high level class for sending direct, market messages to other nodes.
        A node will need one of these to participate in buying and selling.
        Should be initialized after the Kademlia server.
        """
        self.kserver = kserver
        self.router = kserver.protocol.router
        self.protocol = MarketProtocol(kserver.node.getProto(), self.router)

    def get_contract(self, guid, contract_hash):
        """
        Will query the given node to fetch a contract given its hash.
        If it doesn't know the ip for the guid, it will issue find_node rpcs
        on the network to find it. If the returned contract doesn't have the
        same hash, it will return None. Both the guid and contract_hash should
        be in raw byte format.
        """
        def get_result(result):
            if digest(result[1][0]) == contract_hash:
                self.cache(result[1][0])
                return json.loads(result[1][0], object_pairs_hook=OrderedDict)
            else:
                return None

        def get_node(node_to_ask):
            if node_to_ask is None:
                return defer.succeed(None)
            d = self.protocol.callGetContract(node_to_ask, contract_hash)
            return d.addCallback(get_result)

        d = self.kserver.get_node(guid)
        return d.addCallback(get_node)

    def get_image(self, guid, image_hash):
        """
        Will query the given node to fetch an image given its hash.
        If it doesn't know the ip for the guid, it will issue find_node rpcs
        on the network to find it. If the returned image doesn't have the
        same hash, it will return None. Both the guid and image_hash should
        be in raw byte format.
        """
        def get_result(result):
            if digest(result[1][0]) == image_hash:
                self.cache(result[1][0])
                return result[1][0]
            else:
                return None

        def get_node(node_to_ask):
            if node_to_ask is None:
                return defer.succeed(None)
            d = self.protocol.callGetImage(node_to_ask, image_hash)
            return d.addCallback(get_result)

        d = self.kserver.get_node(guid)
        return d.addCallback(get_node)

    def cache(self, file):
        """
        Saves the file to a cache folder if it doesn't already exist.
        """
        if not os.path.exists(DATA_FOLDER + "cache"):
            os.makedirs(DATA_FOLDER + "cache")

        if not os.path.isfile(DATA_FOLDER + "cache/" + digest(file).encode("hex")):
            with open(DATA_FOLDER + "cache/" + digest(file).encode("hex"), 'w') as outfile:
                outfile.write(file)
