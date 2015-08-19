__author__ = 'chris'
from protos.objects import Metadata, Following
from dht.utils import digest
from db.datastore import NotificationStore

m = Metadata()
m.name = "chris"
#m.handle = "hello"
m.avatar_hash = digest("avi")
m.nsfw = True

f = Following()
u = f.User()
u.guid = digest("guid")
u.signed_pubkey = digest("keys")
u.metadata.MergeFrom(m)
u.signature = digest("sig")
print type(u.metadata.handle)

n = NotificationStore()
n.save_notification(digest("guid"), u.metadata.handle, "asdfa", 12345, digest("hash"))
print n.get_notifications()
