"""
An implementation of the kademlia protocol based on https://github.com/bmuller/kademlia
and modified for use in OpenBazaar.

Modifications include:
    Protobuf for serializing the wire protocol.
    The 'STORE' rpc call which appends data to stored dictionaries. Useful for keyword searches.
    A 'DELETE' rpc which allows data to be removed from the DHT when a valid signature is presented.
    RUDP in place of straight UDP.
    The node ID is generated using a proof of work and validated when a new message is received.
"""
version_info = (0, 1)
version = '.'.join([str(i) for i in version_info])
