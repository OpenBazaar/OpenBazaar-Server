__author__ = 'chris'

import bleach
import json
import time
import random
from interfaces import MessageListener, BroadcastListener, NotificationListener
from zope.interface import implements
from protos.objects import PlaintextMessage, Following
from dht.utils import digest

ALLOWED_TAGS = ('h2', 'h3', 'h4', 'h5', 'h6', 'p', 'a', 'u', 'ul', 'ol', 'nl', 'li', 'b', 'i', 'strong',
                'em', 'strike', 'hr', 'br', 'img', 'blockquote')


class MessageListenerImpl(object):
    implements(MessageListener)

    def __init__(self, web_socket_factory, database):
        self.ws = web_socket_factory
        self.db = database.MessageStore()

    def notify(self, plaintext, signature):
        try:
            self.db.save_message(plaintext.sender_guid.encode("hex"), plaintext.handle, plaintext.pubkey,
                                 plaintext.subject, PlaintextMessage.Type.Name(plaintext.type), plaintext.message,
                                 plaintext.timestamp, plaintext.avatar_hash, signature, False)

            # TODO: should probably resolve the handle and make sure it matches the guid

            message_json = {
                "message": {
                    "sender": plaintext.sender_guid.encode("hex"),
                    "subject": plaintext.subject,
                    "message_type": PlaintextMessage.Type.Name(plaintext.type),
                    "message": plaintext.message,
                    "timestamp": plaintext.timestamp,
                    "avatar_hash": plaintext.avatar_hash.encode("hex"),
                    "public_key": plaintext.pubkey.encode("hex")
                }
            }
            if plaintext.handle:
                message_json["message"]["handle"] = plaintext.handle
            self.ws.push(str(bleach.clean(json.dumps(message_json, indent=4), tags=ALLOWED_TAGS)))
        except Exception:
            pass


class BroadcastListenerImpl(object):
    implements(BroadcastListener)

    def __init__(self, web_socket_factory, database):
        self.ws = web_socket_factory
        self.db = database

    def notify(self, guid, message):
        # pull the metadata for this node from the db
        f = Following()
        ser = self.db.FollowData().get_following()
        if ser is not None:
            f.ParseFromString(ser)
            for user in f.users:
                if user.guid == guid:
                    avatar_hash = user.metadata.avatar_hash
                    handle = user.metadata.handle
        timestamp = int(time.time())
        broadcast_id = digest(random.getrandbits(255)).encode("hex")
        self.db.BroadcastStore().save_broadcast(broadcast_id, guid.encode("hex"), handle, message,
                                                timestamp, avatar_hash)
        broadcast_json = {
            "broadcast": {
                "id": broadcast_id,
                "guid": guid.encode("hex"),
                "handle": handle,
                "message": message,
                "timestamp": timestamp,
                "avatar_hash": avatar_hash.encode("hex")
            }
        }
        self.ws.push(str(bleach.clean(json.dumps(broadcast_json, indent=4), tags=ALLOWED_TAGS)))


class NotificationListenerImpl(object):
    implements(NotificationListener)

    def __init__(self, web_socket_factory, database):
        self.ws = web_socket_factory
        self.db = database

    def notify(self, guid, handle, notif_type, order_id, title, image_hash):
        timestamp = int(time.time())
        notif_id = digest(random.getrandbits(255)).encode("hex")
        self.db.NotificationStore().save_notification(notif_id, guid.encode("hex"), handle, notif_type, order_id,
                                                      title, timestamp, image_hash)
        notification_json = {
            "notification": {
                "id": notif_id,
                "guid": guid.encode("hex"),
                "handle": handle,
                "type": notif_type,
                "order_id": order_id,
                "title": title,
                "timestamp": timestamp,
                "image_hash": image_hash.encode("hex")
            }
        }
        self.ws.push(str(bleach.clean(json.dumps(notification_json, indent=4), tags=ALLOWED_TAGS)))
