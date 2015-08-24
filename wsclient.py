__author__ = 'chris'
import json
from twisted.internet import reactor
from autobahn.twisted.websocket import WebSocketClientFactory, \
    WebSocketClientProtocol, \
    connectWS
from dht.utils import digest


class BroadcastClientProtocol(WebSocketClientProtocol):
    """
    Use for testing websocket api
    """
    def sendHello(self):
        request = {
            "request": {
                "api": "v1",
                "id": digest("some_id").encode("hex"),
                "command": "get_homepage_listings"
            }
        }
        self.sendMessage(json.dumps(request, indent=4))

    def onOpen(self):
        self.sendHello()

    def onMessage(self, payload, isBinary):
        print payload


if __name__ == '__main__':

    factory = WebSocketClientFactory("ws://127.0.0.1:18466")
    factory.protocol = BroadcastClientProtocol
    connectWS(factory)

    reactor.run()
