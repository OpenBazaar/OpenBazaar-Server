__author__ = 'chris'
"""
This protocol class handles all direct (non-kademlia) messages between nodes.
All of the messages between a buyer and a vendor's store can be found here.
"""
import json

from zope.interface import implements

from rpcudp import RPCProtocol
from interfaces import MessageProcessor
from log import Logger

from protos.message import GET_CONTRACT

from constants import DATA_FOLDER

class MarketProtocol(RPCProtocol):
    implements(MessageProcessor)

    def __init__(self, node_proto, router):
        self.router = router
        RPCProtocol.__init__(self, node_proto, router)
        self.log = Logger(system=self)
        self.handled_commands = [GET_CONTRACT]

    def connect_multiplexer(self, multiplexer):
        self.multiplexer = multiplexer

    def rpc_get_contract(self, sender, contract_hash):
        self.log.info("Looking up contract ID" % long(contract_hash.encode('hex'), 16))
        self.router.addContact(sender)
        try:
            with open (DATA_FOLDER + "/store/listings/contracts/" + contract_hash + ".json", "r") as file:
                contract = file.read()
            return contract
        except:
            return None

    def call_get_contract(self, nodeToAsk, contract_hash):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_contract(address, contract_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def handleCallResponse(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if result[0]:
            self.log.info("got response from %s, adding to router" % node)
            self.router.addContact(node)
        else:
            self.log.debug("no response from %s, removing from router" % node)
            self.router.removeContact(node)
        return result

    def __iter__(self):
        return iter(self.handled_commands)
