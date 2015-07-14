__author__ = 'chris'

from dht.kprotocol import Node
from dht.utils import digest

n = Node()
n.guid = digest("s")
n.ip = "127.0.0.1"
n.port = 1234
n.signedPublicKey = digest("a")

print n
print n.SerializeToString()
print n.vendor