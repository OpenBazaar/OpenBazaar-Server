__author__ = 'chris'
"""
This protocol class handles all direct (non-kademlia) messages between nodes.
All of the messages between a buyer and a vendor's store can be found here.
"""

from rpcudp import RPCProtocol

class MarketProtocol(RPCProtocol):

    def __init__(self):
        """

        """