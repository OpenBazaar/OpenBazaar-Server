__author__ = 'chris'

import json

from market.protocol import MarketProtocol

from dht.utils import digest

from collections import OrderedDict

from binascii import unhexlify

class Server(object):

    def __init__(self, kserver):
        self.kserver = kserver
        self.router = kserver.protocol.router
        self.protocol = MarketProtocol(kserver.node.getProto(), self.router)

    def get_contract(self, guid, contract_hash):
        def get_result(result):
            if digest(result[1][0]) == contract_hash:
                return json.loads(result[1][0], object_pairs_hook=OrderedDict)
            else:
                return None
        node_to_ask = self.kserver.get_node(guid)
        if node_to_ask is None:
            return None
        d = self.protocol.callGetContract(node_to_ask, contract_hash)
        return d.addCallback(get_result)