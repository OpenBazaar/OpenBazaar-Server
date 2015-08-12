__author__ = 'chris'
import nacl.signing
from zope.interface import implements
from rpcudp import RPCProtocol
from interfaces import MessageProcessor
from log import Logger
from protos.message import *
from db.datastore import HashMap, ListingsStore, FollowData
from market.profile import Profile
from protos.objects import Metadata, Listings, Followers
from binascii import hexlify
from zope.interface.verify import verifyObject
from interfaces import NotificationListener



class MarketProtocol(RPCProtocol):
    implements(MessageProcessor)

    def __init__(self, node_proto, router, signing_key):
        self.router = router
        RPCProtocol.__init__(self, node_proto, router)
        self.log = Logger(system=self)
        self.multiplexer = None
        self.hashmap = HashMap()
        self.signing_key = signing_key
        self.listeners = []
        self.handled_commands = [GET_CONTRACT, GET_IMAGE, GET_PROFILE, GET_LISTINGS, GET_USER_METADATA,
                                 GET_CONTRACT_METADATA, FOLLOW, UNFOLLOW, GET_FOLLOWERS, GET_FOLLOWING,
                                 NOTIFY]

    def connect_multiplexer(self, multiplexer):
        self.multiplexer = multiplexer

    def add_listener(self, listener):
        self.listeners.append(listener)

    def rpc_get_contract(self, sender, contract_hash):
        self.log.info("Looking up contract ID %s" % contract_hash.encode('hex'))
        self.router.addContact(sender)
        try:
            with open(self.hashmap.get_file(contract_hash), "r") as file:
                contract = file.read()
            return [contract]
        except Exception:
            self.log.warning("Could not find contract %s" % contract_hash.encode('hex'))
            return ["None"]

    def rpc_get_image(self, sender, image_hash):
        self.log.info("Looking up image with hash %s" % image_hash.encode('hex'))
        self.router.addContact(sender)
        try:
            with open(self.hashmap.get_file(image_hash), "r") as file:
                image = file.read()
            return [image]
        except Exception:
            self.log.warning("Could not find image %s" % image_hash.encode('hex'))
            return ["None"]

    def rpc_get_profile(self, sender):
        self.log.info("Fetching profile")
        self.router.addContact(sender)
        try:
            proto = Profile().get(True)
            return [proto, self.signing_key.sign(proto)[:64]]
        except Exception:
            self.log.error("Unable to load the profile")
            return ["None"]

    def rpc_get_user_metadata(self, sender):
        self.log.info("Fetching metadata")
        self.router.addContact(sender)
        try:
            proto = Profile().get(False)
            m = Metadata()
            m.name = proto.name
            m.handle = proto.handle
            m.avatar_hash = proto.avatar_hash
            m.nsfw = proto.nsfw
            return [m.SerializeToString(), self.signing_key.sign(m.SerializeToString())[:64]]
        except Exception:
            self.log.error("Unable to get the profile metadata")
            return ["None"]

    def rpc_get_listings(self, sender):
        self.log.info("Fetching listings")
        self.router.addContact(sender)
        try:
            proto = ListingsStore().get_proto()
            return [proto, self.signing_key.sign(proto)[:64]]
        except Exception:
            self.log.warning("Could not find any listings in the database")
            return ["None"]

    def rpc_get_contract_metadata(self, sender, contract_hash):
        self.log.info("Fetching metadata for contract %s" % hexlify(contract_hash))
        self.router.addContact(sender)
        try:
            proto = ListingsStore().get_proto()
            l = Listings()
            l.ParseFromString(proto)
            for listing in l.listing:
                if listing.contract_hash == contract_hash:
                    country_code = Profile().get().country_code
                    listing.country_code = country_code
                    ser = listing.SerializeToString()
            return [ser, self.signing_key.sign(ser)[:64]]
        except Exception:
            self.log.warning("Could not find metadata for contract %s" % hexlify(contract_hash))
            return ["None"]

    def rpc_follow(self, sender, proto, signature):
        self.log.info("Follow request from %s" % sender.id.encode("hex"))
        self.router.addContact(sender)
        try:
            verify_key = nacl.signing.VerifyKey(sender.signed_pubkey[64:])
            verify_key.verify(proto, signature)
            f = Followers.Follower()
            f.ParseFromString(proto)
            if f.guid != sender.id:
                raise Exception('GUID does not match sending node')
            if f.following != self.proto.guid:
                raise Exception('Following wrong node')
            f.signature = signature
            FollowData().set_follower(f)
            proto = Profile().get(False)
            m = Metadata()
            m.name = proto.name
            m.handle = proto.handle
            m.avatar_hash = proto.avatar_hash
            m.nsfw = proto.nsfw
            return ["True", m.SerializeToString(), self.signing_key.sign(m.SerializeToString())[:64]]
        except Exception:
            self.log.warning("Failed to validate follower")
            return ["False"]

    def rpc_unfollow(self, sender, signature):
        self.log.info("Unfollow request from %s" % sender.id.encode("hex"))
        self.router.addContact(sender)
        try:
            verify_key = nacl.signing.VerifyKey(sender.signed_pubkey[64:])
            verify_key.verify("unfollow:" + self.proto.guid, signature)
            f = FollowData()
            f.delete_follower(sender.id)
            return ["True"]
        except Exception:
            self.log.warning("Failed to validate follower signature")
            return ["False"]

    def rpc_get_followers(self, sender):
        self.log.info("Fetching followers list from db")
        self.router.addContact(sender)
        ser = FollowData().get_followers()
        if ser is None:
            return ["None"]
        else:
            return [ser, self.signing_key.sign(ser)[:64]]

    def rpc_get_following(self, sender):
        self.log.info("Fetching following list from db")
        self.router.addContact(sender)
        ser = FollowData().get_following()
        if ser is None:
            return ["None"]
        else:
            return [ser, self.signing_key.sign(ser)[:64]]

    def rpc_notify(self, sender, message):
        if len(message) <= 140 and FollowData().is_following(sender.id):
            self.log.info("Received a notification from %s" % sender)
            self.router.addContact(sender)
            for listener in self.listeners:
                if verifyObject(NotificationListener, listener):
                    listener.notify(message)
            return ["True"]
        else:
            return ["False"]

    def callGetContract(self, nodeToAsk, contract_hash):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_contract(address, contract_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetImage(self, nodeToAsk, image_hash):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_image(address, image_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetProfile(self, nodeToAsk):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_profile(address)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetUserMetadata(self, nodeToAsk):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_user_metadata(address)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetListings(self, nodeToAsk):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_listings(address)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetContractMetadata(self, nodeToAsk, contract_hash):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_contract_metadata(address, contract_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callFollow(self, nodeToAsk, proto, signature):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.follow(address, proto, signature)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callUnfollow(self, nodeToAsk, signature):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.unfollow(address, signature)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetFollowers(self, nodeToAsk):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_followers(address)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetFollowing(self, nodeToAsk):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.get_following(address)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callNotify(self, nodeToAsk, message):
        address = (nodeToAsk.ip, nodeToAsk.port)
        d = self.notify(address, message)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def handleCallResponse(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if result[0]:
            self.log.info("got response from %s, adding to router" % node)
            self.router.addContact(node)
        else:
            self.log.debug("no response from %s, removing from router" % node)
            self.router.removeContact(node)
        return result

    def __iter__(self):
        return iter(self.handled_commands)
