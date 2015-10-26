__author__ = 'chris'
import json
import random
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
                "id": digest(random.getrandbits(128)).encode("hex"),
                "command": "get_homepage_listings",
                "keyword": "furniture",
                "message": "Hello World!",
                "subject": "yo!",
                "handle": "@vintage",
                "guid": "5aef2616b37496d65e06f8413724167811756af5",
                "message_type": "CHAT",
                "recipient_key": "769fd0d4f24cdeef820c28dc1df71d3b47ccf2403c8e205dfb89b21fee61c673"
            }
        }
        self.sendMessage(json.dumps(request, indent=4))

    def onOpen(self):
        self.sendHello()

    def onMessage(self, payload, isBinary):
        print payload


if __name__ == '__main__':

    factory = WebSocketClientFactory("ws://localhost:18466")
    factory.protocol = BroadcastClientProtocol
    connectWS(factory)

    reactor.run()
