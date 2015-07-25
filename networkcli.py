__author__ = 'chris'
import sys
import argparse
import json

from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy

from binascii import hexlify, unhexlify

from dht.utils import digest

from txjsonrpc.netstring import jsonrpc

from market.profile import Profile

from protos import objects

from db.datastore import HashMap

def do_continue(value):
    pass


def print_value(value):
    print json.dumps(value, indent=4)
    reactor.stop()


def print_error(error):
    print 'error', error
    reactor.stop()


class Parser(object):
    def __init__(self, proxy):
        parser = argparse.ArgumentParser(
            description='OpenBazaar Network CLI',
            usage='''
    python network-cli.py command [<arguments>]

commands:
    getinfo          returns an object containing various state info
    getpeers         returns the id of all the peers in the routing table
    get              fetches the given keyword from the dht
    set              sets the given keyword/key in the dht
    delete           deletes the keyword/key from the dht
    getnode          returns a node's ip address given its guid.
    getcontract      fetchs a contract from a node given its hash and guid
    getimage         fetches an image from a node given its hash and guid
    getprofile       fetches the profile from the given node.
    setprofile       sets the given profile data in the database
    shutdown         closes all outstanding connections.
''')
        parser.add_argument('command', help='Execute the given command')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            parser.print_help()
            exit(1)
        getattr(self, args.command)()
        self.proxy = proxy

    def get(self):
        parser = argparse.ArgumentParser(
            description="Fetch the given keyword from the dht and return all the entries",
            usage='''usage:
    network-cli.py get [-kw KEYWORD]''')
        parser.add_argument('-kw', '--keyword', required=True, help="the keyword to fetch")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        d = proxy.callRemote('get', keyword)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def set(self):
        parser = argparse.ArgumentParser(
            description='Set the given keyword/key pair in the dht. The value will be your '
                        'serialized node information.',
            usage='''usage:
    network-cli.py set [-kw KEYWORD] [-k KEY]''')
        parser.add_argument('-kw', '--keyword', required=True, help="the keyword to set in the dht")
        parser.add_argument('-k', '--key', required=True, help="the key to set at the keyword")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        key = args.key
        d = proxy.callRemote('set', keyword, key)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def delete(self):
        parser = argparse.ArgumentParser(
            description="Deletes the given keyword/key from the dht. Signature will be automatically generated.",
            usage='''usage:
    network-cli.py delete [-kw KEYWORD] [-k KEY]''')
        parser.add_argument('-kw', '--keyword', required=True, help="where to find the key")
        parser.add_argument('-k', '--key', required=True, help="the key to delete")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        key = args.key
        d = proxy.callRemote('delete', keyword, key)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getinfo(self):
        parser = argparse.ArgumentParser(
            description="Returns an object containing various state info",
            usage='''usage:
    network-cli getinfo''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getinfo')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def shutdown(self):
        parser = argparse.ArgumentParser(
            description="Terminates all outstanding connections.",
            usage='''usage:
    network-cli shutdown''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('shutdown')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getpubkey(self):
        parser = argparse.ArgumentParser(
            description="Returns this node's public key.",
            usage='''usage:
    network-cli getpubkey''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getpubkey')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getcontract(self):
        parser = argparse.ArgumentParser(
            description="Fetch a contract given its hash and guid.",
            usage='''usage:
    network-cli.py getcontract [-c HASH] [-g GUID]''')
        parser.add_argument('-c', '--hash', required=True, help="the hash of the contract")
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        hash = args.hash
        guid = args.guid
        d = proxy.callRemote('getcontract', hash, guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getimage(self):
        parser = argparse.ArgumentParser(
            description="Fetch an image given its hash and guid.",
            usage='''usage:
    network-cli.py getcontract [-i HASH] [-g GUID]''')
        parser.add_argument('-i', '--hash', required=True, help="the hash of the image")
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        hash = args.hash
        guid = args.guid
        d = proxy.callRemote('getimage', hash, guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getpeers(self):
        parser = argparse.ArgumentParser(
            description="Returns id of all peers in the routing table",
            usage='''usage:
    network-cli getpeers''')
        d = proxy.callRemote('getpeers')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getnode(self):
        parser = argparse.ArgumentParser(
            description="Fetch the ip address for a node given its guid.",
            usage='''usage:
    network-cli.py getnode [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to find")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getnode', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def setprofile(self):
        parser = argparse.ArgumentParser(
            description="Sets a profile in the database.",
            usage='''usage:
    network-cli.py setprofile [options]''')
        parser.add_argument('-n', '--name', help="the name of the user/store")
        parser.add_argument('-o', '--onename', help="the onename id")
        parser.add_argument('-a', '--avatar', help="the file path to the avatar image")
        parser.add_argument('-hd', '--header', help="the file path to the header image")
        # we could add all the fields here but this is good enough to test.
        args = parser.parse_args(sys.argv[2:])
        p = Profile()
        u = objects.Profile()
        h = HashMap()
        if args.name is not None:
            u.name = args.name
        if args.onename is not None:
            u.name = args.onename
        if args.avatar is not None:
            with open(args.avatar, "r") as file:
                image = file.read()
            hash = digest(image)
            u.avatar_hash = hash
            h.insert(hash, args.avatar)
        if args.header is not None:
            with open(args.header, "r") as file:
                image = file.read()
            hash = digest(image)
            u.header_hash = hash
            h.insert(hash, args.header)
        p.update(u)

    def getprofile(self):
        parser = argparse.ArgumentParser(
            description="Fetch the profile from the given node. Images will be saved in cache.",
            usage='''usage:
    network-cli.py getprofile [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getprofile', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

# RPC-Server
class RPCCalls(jsonrpc.JSONRPC):
    def __init__(self, kserver, mserver):
        self.kserver = kserver
        self.mserver = mserver

    def jsonrpc_getpubkey(self):
        return hexlify(g.signed_pubkey)

    def jsonrpc_getinfo(self):
        info = {"version": "0.1"}
        num_peers = 0
        for bucket in self.kserver.protocol.router.buckets:
            num_peers += bucket.__len__()
        info["known peers"] = num_peers
        info["stored messages"] = len(self.kserver.storage.data)
        size = sys.getsizeof(self.kserver.storage.data)
        size += sum(map(sys.getsizeof, self.kserver.storage.data.itervalues())) + sum(
            map(sys.getsizeof, self.kserver.storage.data.iterkeys()))
        info["db size"] = size
        return info

    def jsonrpc_set(self, keyword, key):
        def handle_result(result):
            print "JSONRPC result:", result

        d = self.kserver.set(str(keyword), digest(key), self.kserver.node.getProto().SerializeToString())
        d.addCallback(handle_result)
        return "Sending store request..."

    def jsonrpc_get(self, keyword):
        def handle_result(result):
            print "JSONRPC result:", result

        d = self.kserver.get(keyword)
        d.addCallback(handle_result)
        return "Sent get request. Check log output for result"

    def jsonrpc_delete(self, keyword, key):
        def handle_result(result):
            print "JSONRPC result:", result

        signature = g.signing_key.sign(digest(key))
        d = self.kserver.delete(str(keyword), digest(key), signature[:64])
        d.addCallback(handle_result)
        return "Sending delete request..."

    def jsonrpc_shutdown(self):
        for addr in self.kserver.protocol:
            connection = self.kserver.protocol._active_connections.get(addr)
            if connection is not None:
                connection.shutdown()
        return "Closing all connections."

    def jsonrpc_getpeers(self):
        peers = []
        for bucket in self.kserver.protocol.router.buckets:
            for node in bucket.getNodes():
                peers.append(node.id.encode("hex"))
        return peers

    def jsonrpc_getnode(self, guid):
        def print_node(node):
            print node.ip, node.port
        d = self.kserver.get_node(unhexlify(guid))
        d.addCallback(print_node)
        return "finding node..."

    def jsonrpc_getcontract(self, contract_hash, guid):
        def get_node(node):
            def print_resp(resp):
                print resp
            if node is not None:
                d = self.mserver.get_contract(node, unhexlify(contract_hash))
                d.addCallback(print_resp)
        d = self.kserver.get_node(unhexlify(guid))
        d.addCallback(get_node)
        return "getting contract..."

    def jsonrpc_getimage(self, image_hash, guid):
        def get_node(node):
            def print_resp(resp):
                print resp
            if node is not None:
                d = self.mserver.get_image(node, unhexlify(image_hash))
                d.addCallback(print_resp)
        d = self.kserver.get_node(unhexlify(guid))
        d.addCallback(get_node)
        return "getting image..."

    def jsonrpc_getprofile(self, guid):
        def get_node(node):
            def print_resp(resp):
                print resp
            if node is not None:
                d = self.mserver.get_profile(node)
                d.addCallback(print_resp)
        d = self.kserver.get_node(unhexlify(guid))
        d.addCallback(get_node)
        return "getting profile..."

if __name__ == "__main__":
    proxy = Proxy('127.0.0.1', 18465)
    Parser(proxy)