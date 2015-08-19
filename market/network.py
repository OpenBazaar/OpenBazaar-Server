__author__ = 'chris'

import time
import json
import os.path
import nacl.signing
import nacl.hash
import nacl.encoding
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from dht import node
from twisted.internet import defer, reactor, task
from market.protocol import MarketProtocol
from dht.utils import digest, deferredDict
from constants import DATA_FOLDER
from protos import objects
from db.datastore import FollowData
from market.profile import Profile
from collections import OrderedDict
from binascii import hexlify, unhexlify


class Server(object):
    def __init__(self, kserver, signing_key):
        """
        A high level class for sending direct, market messages to other nodes.
        A node will need one of these to participate in buying and selling.
        Should be initialized after the Kademlia server.
        """
        self.kserver = kserver
        self.signing_key = signing_key
        self.router = kserver.protocol.router
        self.protocol = MarketProtocol(kserver.node.getProto(), self.router, signing_key)

    def get_contract(self, node_to_ask, contract_hash):
        """
        Will query the given node to fetch a contract given its hash.
        If the returned contract doesn't have the same hash, it will return None.

        After acquiring the contract it will download all the associated images if it
        does not already have them in cache.

        Args:
            node_to_ask: a `dht.node.Node` object containing an ip and port
            contract_hash: a 20 byte hash in raw byte format
        """

        def get_result(result):
            if digest(result[1][0]) == contract_hash:
                contract = json.loads(result[1][0], object_pairs_hook=OrderedDict)
                try:
                    signature = contract["vendor_offer"]["signatures"]["guid"]
                    pubkey = node_to_ask.signed_pubkey[64:]
                    verify_key = nacl.signing.VerifyKey(pubkey)
                    verify_key.verify(json.dumps(contract["vendor_offer"]["listing"], indent=4),
                                      unhexlify(signature))
                except Exception:
                    return None
                self.cache(result[1][0])
                if "image_hashes" in contract["vendor"]["listing"]["item"]:
                    for image_hash in contract["vendor"]["listing"]["item"]["image_hashes"]:
                        self.get_image(node_to_ask, unhexlify(image_hash))
                return contract
            else:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetContract(node_to_ask, contract_hash)
        return d.addCallback(get_result)

    def get_image(self, node_to_ask, image_hash):
        """
        Will query the given node to fetch an image given its hash.
        If the returned image doesn't have the same hash, it will return None.

        Args:
            node_to_ask: a `dht.node.Node` object containing an ip and port
            image_hash: a 20 byte hash in raw byte format
        """

        def get_result(result):
            if digest(result[1][0]) == image_hash:
                self.cache(result[1][0])
                return result[1][0]
            else:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetImage(node_to_ask, image_hash)
        return d.addCallback(get_result)

    def get_profile(self, node_to_ask):
        """
        Downloads the profile from the given node. If the images do not already
        exist in cache, it will download and cache them before returning the profile.
        """

        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                p = objects.Profile()
                p.ParseFromString(result[1][0])
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(p.avatar_hash)):
                    self.get_image(node_to_ask, p.avatar_hash)
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(p.header_hash)):
                    self.get_image(node_to_ask, p.header_hash)
                return p
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetProfile(node_to_ask)
        return d.addCallback(get_result)

    def get_user_metadata(self, node_to_ask):
        """
        Downloads just a small portion of the profile (containing the name, handle,
        and avatar hash). We need this for some parts of the UI where we list stores.
        Since we need fast loading we shouldn't download the full profile here.
        It will download the avatar if it isn't already in cache.
        """

        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                m = objects.Metadata()
                m.ParseFromString(result[1][0])
                if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(m.avatar_hash)):
                    self.get_image(node_to_ask, m.avatar_hash)
                return m
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetUserMetadata(node_to_ask)
        return d.addCallback(get_result)

    def get_listings(self, node_to_ask):
        """
        Queries a store for it's list of contracts. A `objects.Listings` protobuf
        is returned containing some metadata for each contract. The individual contracts
        should be fetched with a get_contract call.
        """

        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                l = objects.Listings()
                l.ParseFromString(result[1][0])
                return l
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetListings(node_to_ask)
        return d.addCallback(get_result)

    def get_contract_metadata(self, node_to_ask, contract_hash):
        """
        Downloads just the metadata for the contract. Useful for displaying
        search results in a list view without downloading the entire contract.
        It will download the thumbnail image if it isn't already in cache.
        """

        def get_result(result):
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(result[1][1] + result[1][0])
                l = objects.Listings().ListingMetadata()
                l.ParseFromString(result[1][0])
                if l.HasField("thumbnail_hash"):
                    if not os.path.isfile(DATA_FOLDER + 'cache/' + hexlify(l.thumbnail_hash)):
                        self.get_image(node_to_ask, l.thumbnail_hash)
                return l
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        d = self.protocol.callGetContractMetadata(node_to_ask, contract_hash)
        return d.addCallback(get_result)

    def get_moderators(self):
        """
        Retrieves moderator list from the dht. Each node is queried
        to get metadata and ensure it's alive for usage.
        """

        def parse_response(moderators):
            if moderators is None:
                return None

            def parse_profiles(responses):
                for k, v in responses.items():
                    if v is None:
                        del responses[k]
                return responses

            ds = {}
            for mod in moderators:
                try:
                    val = objects.Value()
                    val.ParseFromString(mod)
                    n = objects.Node()
                    n.ParseFromString(val.serializedData)
                    ds[val.serializedData] = self.get_profile(node.Node(n.guid, n.ip, n.port, n.signedPublicKey))
                except Exception:
                    pass
            return deferredDict(ds).addCallback(parse_profiles)

        return self.kserver.get("moderators").addCallback(parse_response)

    def make_moderator(self):
        """
        Set self as a moderator in the DHT.
        """

        proto = self.kserver.node.getProto().SerializeToString()
        self.kserver.set("moderators", digest(proto), proto)

    def unmake_moderator(self):
        """
        Deletes our moderator entry from the network.
        """

        key = digest(self.kserver.node.getProto().SerializeToString())
        signature = self.signing_key.sign(key)[:64]
        self.kserver.delete("moderators", key, signature)

    def follow(self, node_to_follow):
        """
        Sends a follow message to another node in the network. The node must be online
        to receive the message. The message contains a signed, serialized `Follower`
        protobuf object which the recipient will store and can send to other nodes,
        proving you are following them. The response is a signed `Metadata` protobuf
        that will store in the db.
        """

        def save_to_db(result):
            if result[0] and result[1][0] == "True":
                try:
                    u = objects.Following.User()
                    u.guid = node_to_follow.id
                    u.signed_pubkey = node_to_follow.signed_pubkey
                    m = objects.Metadata()
                    m.ParseFromString(result[1][1])
                    u.metadata.MergeFrom(m)
                    u.signature = result[1][2]
                    pubkey = node_to_follow.signed_pubkey[64:]
                    verify_key = nacl.signing.VerifyKey(pubkey)
                    verify_key.verify(result[1][1], result[1][2])
                    FollowData().follow(u)
                    return True
                except Exception:
                    return False
            else:
                return False

        proto = Profile().get(False)
        m = objects.Metadata()
        m.name = proto.name
        m.handle = proto.handle
        m.avatar_hash = proto.avatar_hash
        m.nsfw = proto.nsfw
        f = objects.Followers.Follower()
        f.guid = self.kserver.node.id
        f.following = node_to_follow.id
        f.signed_pubkey = self.kserver.node.signed_pubkey
        f.metadata.MergeFrom(m)
        signature = self.signing_key.sign(f.SerializeToString())[:64]
        d = self.protocol.callFollow(node_to_follow, f.SerializeToString(), signature)
        return d.addCallback(save_to_db)

    def unfollow(self, node_to_unfollow):
        """
        Sends an unfollow message to a node and removes them from our db.
        """

        def save_to_db(result):
            if result[0] and result[1][0] == "True":
                FollowData().unfollow(node_to_unfollow.id)
                return True
            else:
                return False

        signature = self.signing_key.sign("unfollow:" + node_to_unfollow.id)[:64]
        d = self.protocol.callUnfollow(node_to_unfollow, signature)
        return d.addCallback(save_to_db)

    def get_followers(self, node_to_ask):
        """
        Query the given node for a list if its followers. The response will be a
        `Followers` protobuf object. We will verify the signature for each follower
        to make sure that node really did follower this user.
        """

        def get_response(response):
            # Verify the signature on the response
            f = objects.Followers()
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(response[1][1] + response[1][0])
                f.ParseFromString(response[1][0])
            except Exception:
                return None
            # Verify the signature and guid of each follower.
            for follower in f.followers:
                try:
                    v_key = nacl.signing.VerifyKey(follower.signed_pubkey[64:])
                    signature = follower.signature
                    follower.ClearField("signature")
                    v_key.verify(follower.SerializeToString(), signature)
                    h = nacl.hash.sha512(follower.signed_pubkey)
                    pow_hash = h[64:128]
                    if int(pow_hash[:6], 16) >= 50 or hexlify(follower.guid) != h[:40]:
                        raise Exception('Invalid GUID')
                    if follower.following != node_to_ask.id:
                        raise Exception('Invalid follower')
                except Exception:
                    f.followers.remove(follower)
            return f

        d = self.protocol.callGetFollowers(node_to_ask)
        return d.addCallback(get_response)

    def get_following(self, node_to_ask):
        """
        Query the given node for a list of users it's following. The return
        is `Following` protobuf object that contains signed metadata for each
        user this node is following. The signature on the metadata is there to
        prevent this node from altering the name/handle/avatar associated with
        the guid.
        """

        def get_response(response):
            # Verify the signature on the response
            f = objects.Following()
            try:
                pubkey = node_to_ask.signed_pubkey[64:]
                verify_key = nacl.signing.VerifyKey(pubkey)
                verify_key.verify(response[1][1] + response[1][0])
                f.ParseFromString(response[1][0])
            except Exception:
                return None
            for user in f.users:
                try:
                    v_key = nacl.signing.VerifyKey(user.signed_pubkey[64:])
                    signature = user.signature
                    v_key.verify(user.metadata.SerializeToString(), signature)
                    h = nacl.hash.sha512(user.signed_pubkey)
                    pow_hash = h[64:128]
                    if int(pow_hash[:6], 16) >= 50 or hexlify(user.guid) != h[:40]:
                        raise Exception('Invalid GUID')
                except Exception:
                    f.users.remove(user)
            return f

        d = self.protocol.callGetFollowing(node_to_ask)
        return d.addCallback(get_response)

    def send_notification(self, message):
        """
        Sends a notification message to all online followers. It will resolve
        each guid before sending the notification. Messages must be less than
        140 characters. Returns the number of followers the notification reached.
        """

        if len(message) > 140:
            return defer.succeed(0)

        def send(nodes):
            def how_many_reached(responses):
                count = 0
                for resp in responses:
                    if resp[1][0] and resp[1][1][0] == "True":
                        count += 1
                return count

            ds = []
            signature = self.signing_key.sign(str(message))[:64]
            for n in nodes:
                if n[1] is not None:
                    ds.append(self.protocol.callNotify(n[1], message, signature))
            return defer.DeferredList(ds).addCallback(how_many_reached)
        dl = []
        f = objects.Followers()
        f.ParseFromString(FollowData().get_followers())
        for follower in f.followers:
            dl.append(self.kserver.resolve(follower.guid))
        return defer.DeferredList(dl).addCallback(send)

    def send_message(self, receiving_node, public_key, message_type, message, subject=None):
        """
        Sends a message to another node. If the node isn't online it
        will be placed in the dht for the node to pick up later.
        """
        pro = Profile().get()
        if len(message) > 1500:
            return
        p = objects.Plaintext_Message()
        p.sender_guid = self.kserver.node.id
        p.signed_pubkey = self.kserver.node.signed_pubkey
        p.encryption_pubkey = PrivateKey(self.signing_key.encode()).public_key.encode()
        p.type = message_type
        p.message = message
        if subject is not None:
            p.subject = subject
        if pro.handle:
            p.handle = pro.handle
        if pro.avatar_hash:
            p.avatar_hash = pro.avatar_hash
        p.timestamp = int(time.time())
        signature = self.signing_key.sign(p.SerializeToString())[:64]
        p.signature = signature

        skephem = PrivateKey.generate()
        pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
        box = Box(skephem, PublicKey(public_key, nacl.encoding.HexEncoder))
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        ciphertext = box.encrypt(p.SerializeToString(), nonce)

        def get_response(response):
            if not response[0]:
                self.kserver.set(receiving_node.id, pkephem, ciphertext)
        self.protocol.callMessage(receiving_node, pkephem, ciphertext).addCallback(get_response)

    def get_messages(self, listener):
        # if the transport hasn't been initialized yet, wait a second
        if self.protocol.multiplexer is None or self.protocol.multiplexer.transport is None:
            return task.deferLater(reactor, 1, self.get_messages, listener)

        def parse_messages(messages):
            if messages is not None:
                for message in messages:
                    try:
                        value = objects.Value()
                        value.ParseFromString(message)
                        try:
                            box = Box(PrivateKey(self.signing_key.encode()), PublicKey(value.valueKey))
                            ciphertext = value.serializedData
                            plaintext = box.decrypt(ciphertext)
                            p = objects.Plaintext_Message()
                            p.ParseFromString(plaintext)
                            signature = p.signature
                            p.ClearField("signature")
                            verify_key = nacl.signing.VerifyKey(p.signed_pubkey[64:])
                            verify_key.verify(p.SerializeToString(), signature)
                            h = nacl.hash.sha512(p.signed_pubkey)
                            pow_hash = h[64:128]
                            if int(pow_hash[:6], 16) >= 50 or hexlify(p.sender_guid) != h[:40]:
                                raise Exception('Invalid guid')
                            listener.notify(p.sender_guid, p.encryption_pubkey, p.subject,
                                            objects.Plaintext_Message.Type.Name(p.type), p.message)
                        except Exception:
                            pass
                        signature = self.signing_key.sign(value.valueKey)[:64]
                        self.kserver.delete(self.kserver.node.id, value.valueKey, signature)
                    except Exception:
                        pass
        self.kserver.get(self.kserver.node.id).addCallback(parse_messages)

    @staticmethod
    def cache(filename):
        """
        Saves the file to a cache folder if it doesn't already exist.
        """
        if not os.path.isfile(DATA_FOLDER + "cache/" + digest(filename).encode("hex")):
            with open(DATA_FOLDER + "cache/" + digest(filename).encode("hex"), 'w') as outfile:
                outfile.write(filename)
