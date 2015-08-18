__author__ = 'chris'
import json
from interfaces import MessageListener
from zope.interface import implements
from db.datastore import MessageStore
from twisted.internet import task, reactor

class MessageListenerImpl(object):
    implements(MessageListener)

    def __init__(self, web_socket_handler):
        self.handler = web_socket_handler
        self.db = MessageStore()

    def notify(self, sender_guid, signed_pubkey, encryption_pubkey,
               subject, message_type, message, timestamp, signature):

        self.db.save_message(sender_guid, signed_pubkey, encryption_pubkey, subject,
                             message_type, message, timestamp, signature)

        message_json = {
            "sender": sender_guid,
            "subject": subject,
            "message_type": message_type,
            "message": message,
            "timestamp": timestamp
        }
        self.send_to_websocket(message_json)

    def send_to_websocket(self, message_json):
        # Wait for the transport to get initialized
        if self.handler.transport is None:
            return task.deferLater(reactor, 1, self.send_to_websocket, message_json)
        self.handler.transport.write(json.dumps(message_json))