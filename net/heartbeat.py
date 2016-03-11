__author__ = 'chris'

import json
from twisted.internet.protocol import Protocol, Factory, connectionDone
from twisted.internet.task import LoopingCall


# pylint: disable=W0232
class HeartbeatProtocol(Protocol):
    """
    Handles new incoming requests coming from a websocket.
    """

    def connectionLost(self, reason=connectionDone):
        self.factory.unregister(self)

    def connectionMade(self):
        self.factory.register(self)

    def dataReceived(self, payload):
        return


class HeartbeatFactory(Factory):

    def __init__(self, only_ip=None):
        if only_ip == None:
            only_ip = ["127.0.0.1"]
        self.only_ip = only_ip
        self.status = "starting up"
        self.protocol = HeartbeatProtocol
        self.libbitcoin = None
        self.clients = []
        LoopingCall(self._heartbeat).start(10, now=True)

    def buildProtocol(self, addr):
        if self.status in ("starting up", "generating GUID") and self.only_ip != ["127.0.0.1"]:
            return
        if addr.host not in self.only_ip and "0.0.0.0" not in self.only_ip:
            return
        return Factory.buildProtocol(self, addr)

    def set_status(self, status):
        self.status = status

    def register(self, client):
        if client not in self.clients:
            self.clients.append(client)
            self._heartbeat()

    def unregister(self, client):
        if client in self.clients:
            self.clients.remove(client)

    def push(self, msg):
        for c in self.clients:
            c.transport.write(msg)

    def _heartbeat(self):
        if self.libbitcoin is not None:
            libbitcoin_status = "online" if self.libbitcoin.connected else "offline"
        else:
            libbitcoin_status = "NA"
        self.push(json.dumps({
            "status": self.status,
            "libbitcoin": libbitcoin_status
        }))
