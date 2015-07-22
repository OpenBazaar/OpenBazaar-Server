__author__ = 'chris'
from market.protocol import MarketProtocol

class Server(object):

    def __init__(self, kserver):
        self.kserver = kserver
        self.router = kserver.router
        self.protocol = MarketProtocol(kserver.node, self.router)

    def get_contract(self, guid, contract_hash):
        def get_result(result):
            return result
        node_to_ask = self.kserver.get_node(guid)
        if node_to_ask is None:
            return None
        d = self.protocol.call_get_contract(guid, contract_hash)
        d.addCallback(get_result)