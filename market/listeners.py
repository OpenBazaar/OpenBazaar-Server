__author__ = 'chris'
import json
from interfaces import MessageListener, NotificationListener
from zope.interface import implements
from db.datastore import MessageStore

class MessageListenerImpl(object):
    implements(MessageListener)

    def __init__(self, web_socket_factory):
        self.ws = web_socket_factory
        self.db = MessageStore()

    def notify(self, sender_guid, signed_pubkey, encryption_pubkey,
               subject, message_type, message, timestamp, signature):

        self.db.save_message(sender_guid, signed_pubkey, encryption_pubkey, subject,
                             message_type, message, timestamp, signature)

        message_json = {
            "message": {
                "sender": sender_guid.encode("hex"),
                "subject": subject,
                "message_type": message_type,
                "message": message,
                "timestamp": timestamp
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
