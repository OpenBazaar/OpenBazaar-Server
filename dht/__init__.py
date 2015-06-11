"""
An implementation of the kademlia protocol based on https://github.com/bmuller/kademlia
and modified for use in OpenBazaar.

Modifications include:
    Protobuf for serializing the wire protocol.
    A 'PUBLISH' rpc call which appends data to stored dictionaries. Useful for keyword searches.
    A 'DELETE' rpc which allows data to be removed from the DHT when a valid signature is presented.

"""
version_info = (0, 1)
version = '.'.join(map(str, version_info))
