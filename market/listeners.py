__author__ = 'chris'
import json
from interfaces import MessageListener, NotificationListener
from zope.interface import implements
from db.datastore import MessageStore
from protos.objects import Plaintext_Message

class MessageListenerImpl(object):
    implements(MessageListener)

    def __init__(self, web_socket_factory):
        self.ws = web_socket_factory
        self.db = MessageStore()

    def notify(self, plaintext, signature):

        self.db.save_message(plaintext.sender_guid, plaintext.signed_pubkey, plaintext.encryption_pubkey,
                             plaintext.subject, Plaintext_Message.Type.Name(plaintext.type), plaintext.message,
                             plaintext.timestamp, signature)

        message_json = {
            "message": {
                "sender": plaintext.sender_guid.encode("hex"),
                "subject": plaintext.subject,
                "message_type": Plaintext_Message.Type.Name(plaintext.type),
                "message": plaintext.message,
                "timestamp": plaintext.timestamp
            }
        }
        self.ws.push(json.dumps(message_json, indent=4))

class NotificationListenerImpl(object):
    implements(NotificationListener)

    def __init__(self, web_socket_factory):
        self.ws = web_socket_factory

    def notify(self, message):
        notification_json = {
            "notification": {
                "message": message
            }
        }
        self.ws.push(json.dumps(notification_json, indent=4))
