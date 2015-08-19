__author__ = 'chris'
import sys
import argparse
import json
import time
from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy
from binascii import hexlify, unhexlify
from dht.utils import digest
from txjsonrpc.netstring import jsonrpc
from market.profile import Profile
from protos import objects, countries
from db.datastore import HashMap
from keyutils.keys import KeyChain
from market.contracts import Contract
from collections import OrderedDict
from interfaces import MessageListener
from zope.interface import implements
from dht.node import Node

def do_continue(value):
    pass


def print_value(value):
    print json.dumps(value, indent=4)
    reactor.stop()


def print_error(error):
    print 'error', error
    reactor.stop()


class Parser(object):
    def __init__(self, proxy_obj):
        parser = argparse.ArgumentParser(
            description='OpenBazaar Network CLI',
            usage='''
    python networkcli.py command [<arguments>]

commands:
    follow              follow a user
    unfollow            unfollow a user
    getinfo             returns an object containing various state info
    getpeers            returns the id of all the peers in the routing table
    get                 fetches the given keyword from the dht
    set                 sets the given keyword/key in the dht
    delete              deletes the keyword/key from the dht
    getnode             returns a node's ip address given its guid.
    getcontract         fetchs a contract from a node given its hash and guid
    getcontractmetadata fetches the metadata (including thumbnail image) for the contract
    getimage            fetches an image from a node given its hash and guid
    getprofile          fetches the profile from the given node.
    getmoderators       fetches a list of moderators
    getusermetadata     fetches the metadata (shortened profile) for the node
    getlistings         fetches metadata about the store's listings
    getfollowers        fetches a list of followers of a node
    getfollowing        fetches a list of users a node is following
    getmessages         fetches messages from the dht
    sendnotification    sends a notification to all your followers
    setcontract         sets a contract in the filesystem and db
    setimage            maps an image hash to a filepath in the db
    setasmoderator      sets a node as a moderator
    setprofile          sets the given profile data in the database
    shutdown            closes all outstanding connections.
''')
        parser.add_argument('command', help='Execute the given command')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            parser.print_help()
            exit(1)
        getattr(self, args.command)()
        self.proxy = proxy_obj

    @staticmethod
    def get():
        parser = argparse.ArgumentParser(
            description="Fetch the given keyword from the dht and return all the entries",
            usage='''usage:
    networkcli.py get [-kw KEYWORD]''')
        parser.add_argument('-kw', '--keyword', required=True, help="the keyword to fetch")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        d = proxy.callRemote('get', keyword)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def set():
        parser = argparse.ArgumentParser(
            description='Set the given keyword/key pair in the dht. The value will be your '
                        'serialized node information.',
            usage='''usage:
    networkcli.py set [-kw KEYWORD] [-k KEY]''')
        parser.add_argument('-kw', '--keyword', required=True, help="the keyword to set in the dht")
        parser.add_argument('-k', '--key', required=True, help="the key to set at the keyword")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        key = args.key
        d = proxy.callRemote('set', keyword, key)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def delete():
        parser = argparse.ArgumentParser(
            description="Deletes the given keyword/key from the dht. Signature will be automatically generated.",
            usage='''usage:
    networkcli.py delete [-kw KEYWORD] [-k KEY]''')
        parser.add_argument('-kw', '--keyword', required=True, help="where to find the key")
        parser.add_argument('-k', '--key', required=True, help="the key to delete")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        key = args.key
        d = proxy.callRemote('delete', keyword, key)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getinfo():
        parser = argparse.ArgumentParser(
            description="Returns an object containing various state info",
            usage='''usage:
    networkcli getinfo''')
        parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getinfo')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def shutdown():
        parser = argparse.ArgumentParser(
            description="Terminates all outstanding connections.",
            usage='''usage:
    networkcli shutdown''')
        parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('shutdown')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getpubkey():
        parser = argparse.ArgumentParser(
            description="Returns this node's public key.",
            usage='''usage:
    networkcli getpubkey''')
        parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getpubkey')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getcontract():
        parser = argparse.ArgumentParser(
            description="Fetch a contract given its hash and guid.",
            usage='''usage:
    networkcli.py getcontract [-c HASH] [-g GUID]''')
        parser.add_argument('-c', '--hash', required=True, help="the hash of the contract")
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        hash_value = args.hash
        guid = args.guid
        d = proxy.callRemote('getcontract', hash_value, guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getimage():
        parser = argparse.ArgumentParser(
            description="Fetch an image given its hash and guid.",
            usage='''usage:
    networkcli.py getcontract [-i HASH] [-g GUID]''')
        parser.add_argument('-i', '--hash', required=True, help="the hash of the image")
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        hash_value = args.hash
        guid = args.guid
        d = proxy.callRemote('getimage', hash_value, guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getpeers():
        parser = argparse.ArgumentParser(
            description="Returns id of all peers in the routing table",
            usage='''usage:
    networkcli getpeers''')
        parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getpeers')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getnode():
        parser = argparse.ArgumentParser(
            description="Fetch the ip address for a node given its guid.",
            usage='''usage:
    networkcli.py getnode [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to find")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getnode', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def setprofile():
        parser = argparse.ArgumentParser(
            description="Sets a profile in the database.",
            usage='''usage:
    networkcli.py setprofile [options]''')
        parser.add_argument('-n', '--name', help="the name of the user/store")
        parser.add_argument('-o', '--onename', help="the onename id")
        parser.add_argument('-a', '--avatar', help="the file path to the avatar image")
        parser.add_argument('-hd', '--header', help="the file path to the header image")
        parser.add_argument('-c', '--country',
                            help="a string consisting of country from protos.countries.CountryCode")
        # we could add all the fields here but this is good enough to test.
        args = parser.parse_args(sys.argv[2:])
        p = Profile()
        u = objects.Profile()
        h = HashMap()
        if args.name is not None:
            u.name = args.name
        if args.country is not None:
            u.location = countries.CountryCode.Value(args.country.upper())
        if args.onename is not None:
            u.handle = args.onename
        if args.avatar is not None:
            with open(args.avatar, "r") as filename:
                image = filename.read()
            hash_value = digest(image)
            u.avatar_hash = hash_value
            h.insert(hash_value, args.avatar)
        if args.header is not None:
            with open(args.header, "r") as filename:
                image = filename.read()
            hash_value = digest(image)
            u.header_hash = hash_value
            h.insert(hash_value, args.header)
        u.encryption_key = KeyChain().encryption_pubkey
        p.update(u)

    @staticmethod
    def getprofile():
        parser = argparse.ArgumentParser(
            description="Fetch the profile from the given node. Images will be saved in cache.",
            usage='''usage:
    networkcli.py getprofile [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getprofile', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getusermetadata():
        parser = argparse.ArgumentParser(
            description="Fetches the metadata (small profile) from"
                        "a given node. The images will be saved in cache.",
            usage='''usage:
    networkcli.py getusermetadata [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getusermetadata', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def setcontract():
        parser = argparse.ArgumentParser(
            description="Sets a new contract in the database and filesystem.",
            usage='''usage:
    networkcli.py setcontract [-f FILEPATH]''')
        parser.add_argument('-f', '--filepath', help="a path to a completed json contract")
        args = parser.parse_args(sys.argv[2:])
        with open(args.filepath) as data_file:
            contract = json.load(data_file, object_pairs_hook=OrderedDict)
        Contract(contract).save()

    @staticmethod
    def setimage():
        parser = argparse.ArgumentParser(
            description="Maps a image hash to a file path in the database",
            usage='''usage:
    networkcli.py setimage [-f FILEPATH]''')
        parser.add_argument('-f', '--filepath', help="a path to the image")
        args = parser.parse_args(sys.argv[2:])
        with open(args.filepath, "r") as f:
            image = f.read()
        d = digest(image)
        h = HashMap()
        h.insert(d, args.filepath)
        print h.get_file(d)

    @staticmethod
    def getlistings():
        parser = argparse.ArgumentParser(
            description="Fetches metadata about the store's listings",
            usage='''usage:
    networkcli.py getmetadata [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getlistings', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getcontractmetadata():
        parser = argparse.ArgumentParser(
            description="Fetches the metadata for the given contract. The thumbnail images will be saved in cache.",
            usage='''usage:
    networkcli.py getcontractmetadata [-g GUID] [-c CONTRACT]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        parser.add_argument('-c', '--contract', required=True, help="the contract hash")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        contract = args.contract
        d = proxy.callRemote('getcontractmetadata', guid, contract)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def setasmoderator():
        parser = argparse.ArgumentParser(
            description="Sets the given node as a moderator.",
            usage='''usage:
    networkcli.py setasmoderator''')
        parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('setasmoderator')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getmoderators():
        parser = argparse.ArgumentParser(
            description="Fetches a list of moderators",
            usage='''usage:
    networkcli.py getmoderators ''')
        parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getmoderators')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def follow():
        parser = argparse.ArgumentParser(
            description="Follow a user",
            usage='''usage:
    networkcli.py follow [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to follow")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('follow', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def unfollow():
        parser = argparse.ArgumentParser(
            description="Unfollow a user",
            usage='''usage:
    networkcli.py unfollow [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to unfollow")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('unfollow', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getfollowers():
        parser = argparse.ArgumentParser(
            description="Get a list of followers of a node",
            usage='''usage:
    networkcli.py getfollowers [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getfollowers', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getfollowing():
        parser = argparse.ArgumentParser(
            description="Get a list users a node is following",
            usage='''usage:
    networkcli.py getfollowing [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to query")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getfollowing', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def sendnotification():
        parser = argparse.ArgumentParser(
            description="Send a notification to all your followers",
            usage='''usage:
    networkcli.py sendnotification [-m MESSAGE]''')
        parser.add_argument('-m', '--message', required=True, help="the message to send")
        args = parser.parse_args(sys.argv[2:])
        message = args.message
        d = proxy.callRemote('sendnotification', message)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def sendmessage():
        parser = argparse.ArgumentParser(
            description="Send a message to another node",
            usage='''usage:
    networkcli.py sendmessage [-g GUID] [-p PUBKEY] [-m MESSAGE] [-o]''')
        parser.add_argument('-g', '--guid', required=True, help="the guid to send to")
        parser.add_argument('-p', '--pubkey', required=True, help="the encryption key of the node")
        parser.add_argument('-m', '--message', required=True, help="the message to send")
        parser.add_argument('-o', '--offline', action='store_true', help="sends to offline recipient")
        args = parser.parse_args(sys.argv[2:])
        message = args.message
        guid = args.guid
        pubkey = args.pubkey
        offline = args.offline
        d = proxy.callRemote('sendmessage', guid, pubkey, message, offline)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    @staticmethod
    def getmessages():
        parser = argparse.ArgumentParser(
            description="Get messages from the dht",
            usage='''usage:
    networkcli.py getmessages''')
        parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getmessages')
        d.addCallbacks(print_value, print_error)
        reactor.run()

# RPC-Server
class RPCCalls(jsonrpc.JSONRPC):
    def __init__(self, kserver, mserver, keys):
        jsonrpc.JSONRPC.__init__(self)
        self.kserver = kserver
        self.mserver = mserver
        self.keys = keys

    def jsonrpc_getpubkey(self):
        return hexlify(self.keys.guid_signed_pubkey)

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
            for mod in result:
                try:
                    val = objects.Value()
                    val.ParseFromString(mod)

                    node = objects.Node()
                    node.ParseFromString(val.serializedData)
                    print node
                except Exception as e:
                    print 'malformed protobuf', e.message

        d = self.kserver.get(keyword)
        d.addCallback(handle_result)
        return "Sent get request. Check log output for result"

    def jsonrpc_delete(self, keyword, key):
        def handle_result(result):
            print "JSONRPC result:", result

        signature = self.keys.signing_key.sign(digest(key))
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
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(print_node)
        return "finding node..."

    def jsonrpc_getcontract(self, contract_hash, guid):
        def get_node(node):
            def print_resp(resp):
                print resp
            if node is not None:
                d = self.mserver.get_contract(node, unhexlify(contract_hash))
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting contract..."

    def jsonrpc_getimage(self, image_hash, guid):
        def get_node(node):
            def print_resp(resp):
                print resp
            if node is not None:
                d = self.mserver.get_image(node, unhexlify(image_hash))
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting image..."

    def jsonrpc_getprofile(self, guid):
        start = time.time()

        def get_node(node):
            def print_resp(resp):
                print time.time() - start
                print resp
                print hexlify(resp.encryption_key)
            if node is not None:
                d = self.mserver.get_profile(node)
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting profile..."

    def jsonrpc_getusermetadata(self, guid):
        start = time.time()

        def get_node(node):
            def print_resp(resp):
                print time.time() - start
                print resp
            if node is not None:
                d = self.mserver.get_user_metadata(node)
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting user metadata..."

    def jsonrpc_getlistings(self, guid):
        start = time.time()

        def get_node(node):
            def print_resp(resp):
                print time.time() - start
                if resp:
                    for l in resp.listing:
                        resp.listing.remove(l)
                        h = l.contract_hash
                        l.contract_hash = hexlify(h)
                        resp.listing.extend([l])
                print resp
            if node is not None:
                d = self.mserver.get_listings(node)
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting listing metadata..."

    def jsonrpc_getcontractmetadata(self, guid, contract_hash):
        start = time.time()

        def get_node(node):
            def print_resp(resp):
                print time.time() - start
                print resp
            if node is not None:
                d = self.mserver.get_contract_metadata(node, unhexlify(contract_hash))
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting contract metadata..."

    def jsonrpc_setasmoderator(self):
        self.mserver.make_moderator()

    def jsonrpc_getmoderators(self):
        def print_mods(mods):
            print mods

        self.mserver.get_moderators().addCallback(print_mods)
        return "finding moderators in dht..."

    def jsonrpc_follow(self, guid):
        def get_node(node):
            if node is not None:
                def print_resp(resp):
                    print resp
                d = self.mserver.follow(node)
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "following node..."

    def jsonrpc_unfollow(self, guid):
        def get_node(node):
            if node is not None:
                def print_resp(resp):
                    print resp
                d = self.mserver.unfollow(node)
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "unfollowing node..."

    def jsonrpc_getfollowers(self, guid):
        def get_node(node):
            if node is not None:
                def print_resp(resp):
                    print resp
                d = self.mserver.get_followers(node)
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting followers..."

    def jsonrpc_getfollowing(self, guid):
        def get_node(node):
            if node is not None:
                def print_resp(resp):
                    print resp
                d = self.mserver.get_following(node)
                d.addCallback(print_resp)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "getting following..."

    def jsonrpc_sendnotification(self, message):
        def get_count(count):
            print "Notification reached %i follower(s)" % count
        d = self.mserver.send_notification(message)
        d.addCallback(get_count)
        return "sendng notification..."

    def jsonrpc_sendmessage(self, guid, pubkey, message, offline=False):
        def get_node(node):
            if node is not None or offline is True:
                if offline is True:
                    node = Node(unhexlify(guid), "127.0.0.1", 1234, digest("adsf"))
                self.mserver.send_message(node, pubkey, objects.Plaintext_Message.CHAT, message)
        d = self.kserver.resolve(unhexlify(guid))
        d.addCallback(get_node)
        return "sending message..."

    def jsonrpc_getmessages(self):
        class GetMyMessages(object):
            implements(MessageListener)

            @staticmethod
            def notify(sender_guid, encryption_pubkey, subject, message_type, message):
                print message
        self.mserer.get_messages(GetMyMessages())
        return "getting messages..."

if __name__ == "__main__":
    proxy = Proxy('127.0.0.1', 18465)
    Parser(proxy)
