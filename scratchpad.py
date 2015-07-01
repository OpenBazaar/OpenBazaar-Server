__author__ = 'chris'
from dht.utils import digest
from dht.kprotocol import Node, Message, FIND_NODE

from binascii import hexlify, unhexlify

n = Node()
n.guid = digest("guid")
n.publicKey = digest("pubkey")
n.ip = "127.0.0.1"
n.port = 1234

for i in range(0, 1):
    m = Message()
    m.messageID = digest("msgID")
    m.sender.MergeFrom(n)
    m.command = FIND_NODE
    m.arguments.append(digest("nodeID"))

    data = m.SerializeToString()

    y =  hexlify(data)

y = unhexlify(y)
m2 = Message()
m2.ParseFromString(y)
print m2