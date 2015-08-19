__author__ = 'chris'
import json
import time
from interfaces import MessageListener, NotificationListener
from zope.interface import implements
from db.datastore import MessageStore, NotificationStore, FollowData
from protos.objects import Plaintext_Message, Following

class MessageListenerImpl(object):
    implements(MessageListener)

    def __init__(self, web_socket_factory):
        self.ws = web_socket_factory
        self.db = MessageStore()

    def notify(self, plaintext, signature):

        self.db.save_message(plaintext.sender_guid, plaintext.handle, plaintext.signed_pubkey,
                             plaintext.encryption_pubkey, plaintext.subject,
                             Plaintext_Message.Type.Name(plaintext.type), plaintext.message,
                             plaintext.avatar_hash, plaintext.timestamp, signature)

        # TODO: should probably resolve the handle and make sure it matches the guid so the sender can't spoof it

        message_json = {
            "message": {
                "sender": plaintext.sender_guid.encode("hex"),
                "subject": plaintext.subject,
                "message_type": Plaintext_Message.Type.Name(plaintext.type),
                "message": plaintext.message,
                "timestamp": plaintext.timestamp,
                "avatar_hash": plaintext.avatar_hash.encode("hex")
            }
        }
        if plaintext.handle:
            message_json["message"]["handle"] = plaintext.handle
        self.ws.push(json.dumps(message_json, indent=4))

class NotificationListenerImpl(object):
    implements(NotificationListener)

    def __init__(self, web_socket_factory):
        self.ws = web_socket_factory

    def notify(self, guid, message):
        # pull the metadata for this node from the db
        f = Following()
        ser = FollowData().get_following()
        if ser is not None:
            f.ParseFromString(ser)
            for user in f.users:
                if user.guid == guid:
                    avatar_hash = user.metadata.avatar_hash
                    handle = user.metadata.handle
        timestamp = int(time.time())
        NotificationStore().save_notification(guid, handle, message, timestamp, avatar_hash)
        notification_json = {
            "notification": {
                "guid": guid.encode("hex"),
                "message": message,
                "timestamp": timestamp,
                "avatar_hash": avatar_hash.encode("hex")
            }
        }
        if handle:
            notification_json["notification"]["handle"] = handle
        self.ws.push(json.dumps(notification_json, indent=4))
