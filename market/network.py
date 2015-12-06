__author__ = 'chris'

import time
import json
import os.path
import nacl.signing
import nacl.hash
import nacl.encoding
import nacl.utils
import gnupg
import bitcoin
from dht.node import Node
from nacl.public import PrivateKey, PublicKey, Box
from twisted.internet import defer, reactor, task
from market.protocol import MarketProtocol
from dht.utils import digest
from constants import DATA_FOLDER
from protos import objects
from market.profile import Profile
from market.contracts import Contract
from collections import OrderedDict
from binascii import unhexlify
from keyutils.keys import KeyChain
from keyutils.bip32utils import derive_childkey
from log import Logger


class Server(object):
    def __init__(self, kserver, signing_key, database):
        """
        A high level class for sending direct, market messages to other nodes.
        A node will need one of these to participate in buying and selling.
        Should be initialized after the Kademlia server.
        """
        self.kserver = kserver
        self.signing_key = signing_key
        self.router = kserver.protocol.router
        self.db = database
        self.log = Logger(system=self)
        self.protocol = MarketProtocol(kserver.node, self.router, signing_key, database)

        # TODO: we need a loop here that republishes keywords when they are about to expire

        # TODO: we also need a loop here to delete expiring contract (if they are set to expire)

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
            try:
                if result[0] and digest(result[1][0]) == contract_hash:
                    contract = json.loads(result[1][0], object_pairs_hook=OrderedDict)

                    # TODO: verify the guid in the contract matches this node's guid
                    signature = contract["vendor_offer"]["signature"]
                    pubkey = node_to_ask.signed_pubkey[64:]
                    verify_key = nacl.signing.VerifyKey(pubkey)
                    verify_key.verify(json.dumps(contract["vendor_offer"]["listing"], indent=4),
                                      unhexlify(signature))
                    if "moderators" in contract["vendor_offer"]["listing"]:
                        for moderator in contract["vendor_offer"]["listing"]["moderators"]:
                            guid = moderator["guid"]
                            guid_key = moderator["pubkeys"]["signing"]["key"]
                            guid_sig = moderator["pubkeys"]["signing"]["signature"]
                            enc_key = moderator["pubkeys"]["encryption"]["key"]
                            enc_sig = moderator["pubkeys"]["encryption"]["signature"]
                            bitcoin_key = moderator["pubkeys"]["bitcoin"]["key"]
                            bitcoin_sig = moderator["pubkeys"]["bitcoin"]["signature"]
                            h = nacl.hash.sha512(unhexlify(guid_sig) + unhexlify(guid_key))
                            pow_hash = h[64:128]
                            if int(pow_hash[:6], 16) >= 50 or guid != h[:40]:
                                raise Exception('Invalid GUID')
                            verify_key = nacl.signing.VerifyKey(guid_key, encoder=nacl.encoding.HexEncoder)
                            verify_key.verify(unhexlify(enc_key), unhexlify(enc_sig))
                            verify_key.verify(unhexlify(bitcoin_key), unhexlify(bitcoin_sig))
                            # should probably also validate the handle here.
                    self.cache(result[1][0])
                    if "image_hashes" in contract["vendor_offer"]["listing"]["item"]:
                        for image_hash in contract["vendor_offer"]["listing"]["item"]["image_hashes"]:
                            self.get_image(node_to_ask, unhexlify(image_hash))
                    return contract
                else:
                    return None
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        self.log.info("fetching contract %s from %s" % (contract_hash.encode("hex"), node_to_ask))
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
            try:
                if result[0] and digest(result[1][0]) == image_hash:
                    self.cache(result[1][0])
                    return result[1][0]
                else:
                    return None
            except Exception:
                return None

        if node_to_ask.ip is None or len(image_hash) != 20:
            return defer.succeed(None)
        self.log.info("fetching image %s from %s" % (image_hash.encode("hex"), node_to_ask))
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
                if p.pgp_key.public_key:
                    gpg = gnupg.GPG()
                    gpg.import_keys(p.pgp_key.publicKey)
                    if not gpg.verify(p.pgp_key.signature) or \
                                    node_to_ask.id.encode('hex') not in p.pgp_key.signature:
                        p.ClearField("pgp_key")
                if not os.path.isfile(DATA_FOLDER + 'cache/' + p.avatar_hash.encode("hex")):
                    self.get_image(node_to_ask, p.avatar_hash)
                if not os.path.isfile(DATA_FOLDER + 'cache/' + p.header_hash.encode("hex")):
                    self.get_image(node_to_ask, p.header_hash)
                return p
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        self.log.info("fetching profile from %s" % node_to_ask)
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
                if not os.path.isfile(DATA_FOLDER + 'cache/' + m.avatar_hash.encode("hex")):
                    self.get_image(node_to_ask, m.avatar_hash)
                return m
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        self.log.info("fetching user metadata from %s" % node_to_ask)
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
        self.log.info("fetching store listings from %s" % node_to_ask)
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
                    if not os.path.isfile(DATA_FOLDER + 'cache/' + l.thumbnail_hash.encode("hex")):
                        self.get_image(node_to_ask, l.thumbnail_hash)
                return l
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        self.log.info("fetching metadata for contract %s from %s" % (contract_hash.encode("hex"), node_to_ask))
        d = self.protocol.callGetContractMetadata(node_to_ask, contract_hash)
        return d.addCallback(get_result)

    def make_moderator(self):
        """
        Set self as a moderator in the DHT.
        """

        u = objects.Profile()
        k = u.PublicKey()
        k.public_key = bitcoin.bip32_deserialize(KeyChain(self.db).bitcoin_master_pubkey)[5]
        k.signature = self.signing_key.sign(k.public_key)[:64]
        u.bitcoin_key.MergeFrom(k)
        u.moderator = True
        Profile(self.db).update(u)
        proto = self.kserver.node.getProto().SerializeToString()
        self.kserver.set(digest("moderators"), digest(proto), proto)
        self.log.info("setting self as moderator on the network")

    def unmake_moderator(self):
        """
        Deletes our moderator entry from the network.
        """

        key = digest(self.kserver.node.getProto().SerializeToString())
        signature = self.signing_key.sign(key)[:64]
        self.kserver.delete("moderators", key, signature)
        Profile(self.db).remove_field("moderator")
        self.log.info("removing self as moderator from the network")

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
                    self.db.FollowData().follow(u)
                    return True
                except Exception:
                    return False
            else:
                return False

        proto = Profile(self.db).get(False)
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
        self.log.info("sending follow request to %s" % node_to_follow)
        return d.addCallback(save_to_db)

    def unfollow(self, node_to_unfollow):
        """
        Sends an unfollow message to a node and removes them from our db.
        """

        def save_to_db(result):
            try:
                if result[0] and result[1][0] == "True":
                    self.db.FollowData().unfollow(node_to_unfollow.id)
                    return True
                else:
                    return False
            except Exception:
                return False

        signature = self.signing_key.sign("unfollow:" + node_to_unfollow.id)[:64]
        d = self.protocol.callUnfollow(node_to_unfollow, signature)
        self.log.info("sending unfollow request to %s" % node_to_unfollow)
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
                    if int(pow_hash[:6], 16) >= 50 or follower.guid.encode("hex") != h[:40]:
                        raise Exception('Invalid GUID')
                    if follower.following != node_to_ask.id:
                        raise Exception('Invalid follower')
                except Exception:
                    f.followers.remove(follower)
            return f

        d = self.protocol.callGetFollowers(node_to_ask)
        self.log.info("fetching followers from %s" % node_to_ask)
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
                    if int(pow_hash[:6], 16) >= 50 or user.guid.encode("hex") != h[:40]:
                        raise Exception('Invalid GUID')
                except Exception:
                    f.users.remove(user)
            return f

        d = self.protocol.callGetFollowing(node_to_ask)
        self.log.info("fetching following list from %s" % node_to_ask)
        return d.addCallback(get_response)

    def broadcast(self, message):
        """
        Sends a broadcast message to all online followers. It will resolve
        each guid before sending the broadcast. Messages must be less than
        140 characters. Returns the number of followers the broadcast reached.
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
                    ds.append(self.protocol.callBroadcast(n[1], message, signature))
            return defer.DeferredList(ds).addCallback(how_many_reached)
        dl = []
        f = objects.Followers()
        f.ParseFromString(self.db.FollowData().get_followers())
        for follower in f.followers:
            dl.append(self.kserver.resolve(follower.guid))
        self.log.info("broadcasting %s to followers" % message)
        return defer.DeferredList(dl).addCallback(send)

    def send_message(self, receiving_node, public_key, message_type, message, subject=None, store_only=False):
        """
        Sends a message to another node. If the node isn't online it
        will be placed in the dht for the node to pick up later.
        """
        pro = Profile(self.db).get()
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
                ciphertext = box.encrypt(p.SerializeToString().encode("zlib"), nonce)
                self.kserver.set(digest(receiving_node.id), pkephem, ciphertext)

        self.log.info("sending encrypted message to %s" % receiving_node.id.encode("hex"))
        if not store_only:
            self.protocol.callMessage(receiving_node, pkephem, ciphertext).addCallback(get_response)
        else:
            get_response([False])

    def get_messages(self, listener):
        # if the transport hasn't been initialized yet, wait a second
        if self.protocol.multiplexer is None or self.protocol.multiplexer.transport is None:
            return task.deferLater(reactor, 1, self.get_messages, listener)

        def parse_messages(messages):
            if messages is not None:
                self.log.info("retrieved %s message(s) from the dht" % len(messages))
                for message in messages:
                    try:
                        value = objects.Value()
                        value.ParseFromString(message)
                        try:
                            box = Box(PrivateKey(self.signing_key.encode()), PublicKey(value.valueKey))
                            ciphertext = value.serializedData
                            plaintext = box.decrypt(ciphertext).decode("zlib")
                            p = objects.Plaintext_Message()
                            p.ParseFromString(plaintext)
                            signature = p.signature
                            p.ClearField("signature")
                            verify_key = nacl.signing.VerifyKey(p.signed_pubkey[64:])
                            verify_key.verify(p.SerializeToString(), signature)
                            h = nacl.hash.sha512(p.signed_pubkey)
                            pow_hash = h[64:128]
                            if int(pow_hash[:6], 16) >= 50 or p.sender_guid.encode("hex") != h[:40]:
                                raise Exception('Invalid guid')
                            if p.type == objects.Plaintext_Message.Type.Value("ORDER_CONFIRMATION"):
                                c = Contract(self.db, hash_value=p.subject)
                                c.accept_order_confirmation(self.protocol.get_notification_listener(),
                                                            confirmation_json=p.message)
                            elif p.type == objects.Plaintext_Message.Type.Value("RECEIPT"):
                                c = Contract(self.db, hash_value=p.subject)
                                c.accept_receipt(self.protocol.get_notification_listener(),
                                                 self.protocol.multiplexer.blockchain,
                                                 receipt_json=p.message)
                            else:
                                listener.notify(p, signature)
                        except Exception:
                            pass
                        signature = self.signing_key.sign(value.valueKey)[:64]
                        self.kserver.delete(self.kserver.node.id, value.valueKey, signature)
                    except Exception:
                        pass
        self.kserver.get(self.kserver.node.id).addCallback(parse_messages)

    def purchase(self, node_to_ask, contract):
        """
        Send an order message to the vendor.

        Args:
            node_to_ask: a `dht.node.Node` object
            contract: a complete `Contract` object containing the buyer's order
        """
        def parse_response(response):
            try:
                address = contract.contract["buyer_order"]["order"]["payment"]["address"]
                chaincode = contract.contract["buyer_order"]["order"]["payment"]["chaincode"]
                masterkey_b = contract.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
                buyer_key = derive_childkey(masterkey_b, chaincode)
                amount = contract.contract["buyer_order"]["order"]["payment"]["amount"]
                listing_hash = contract.contract["buyer_order"]["order"]["ref_hash"]
                verify_key = nacl.signing.VerifyKey(node_to_ask.signed_pubkey[64:])
                verify_key.verify(
                    str(address) + str(amount) + str(listing_hash) + str(buyer_key), response[1][0])
                return response[1][0]
            except Exception:
                return False

        public_key = contract.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["encryption"]
        skephem = PrivateKey.generate()
        pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
        box = Box(skephem, PublicKey(public_key, nacl.encoding.HexEncoder))
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        ciphertext = box.encrypt(json.dumps(contract.contract, indent=4), nonce)
        d = self.protocol.callOrder(node_to_ask, pkephem, ciphertext)
        self.log.info("purchasing contract %s from %s" % (contract.get_contract_id().encode("hex"), node_to_ask))
        return d.addCallback(parse_response)

    def confirm_order(self, guid, contract):
        """
        Send the order confirmation over to the buyer. If the buyer isn't
        online we will stick it in the DHT temporarily.
        """

        def get_node(node_to_ask):
            def parse_response(response):
                if response[0] and response[1][0] == "True":
                    return True
                elif not response[0]:
                    contract_dict = json.loads(json.dumps(contract.contract, indent=4),
                                               object_pairs_hook=OrderedDict)
                    del contract_dict["vendor_order_confirmation"]
                    order_id = digest(json.dumps(contract_dict, indent=4)).encode("hex")
                    self.send_message(Node(unhexlify(guid)),
                                      contract.contract["buyer_order"]["order"]["id"]["pubkeys"]["encryption"],
                                      objects.Plaintext_Message.Type.Value("ORDER_CONFIRMATION"),
                                      json.dumps(contract.contract["vendor_order_confirmation"]),
                                      order_id,
                                      store_only=True)
                    return True
                else:
                    return False

            if node_to_ask:
                public_key = contract.contract["buyer_order"]["order"]["id"]["pubkeys"]["encryption"]
                skephem = PrivateKey.generate()
                pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                box = Box(skephem, PublicKey(public_key, nacl.encoding.HexEncoder))
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt(json.dumps(contract.contract, indent=4), nonce)
                d = self.protocol.callOrderConfirmation(node_to_ask, pkephem, ciphertext)
                return d.addCallback(parse_response)
            else:
                return parse_response([False])
        self.log.info("sending order confirmation to %s" % guid)
        return self.kserver.resolve(unhexlify(guid)).addCallback(get_node)

    def complete_order(self, guid, contract):
        """
        Send the receipt, including the payout signatures and ratings, over to the vendor.
        If the vendor isn't online we will stick it in the DHT temporarily.
        """

        def get_node(node_to_ask):
            def parse_response(response):
                if response[0] and response[1][0] == "True":
                    return True
                elif not response[0]:
                    contract_dict = json.loads(json.dumps(contract.contract, indent=4),
                                               object_pairs_hook=OrderedDict)
                    del contract_dict["vendor_order_confirmation"]
                    del contract_dict["buyer_receipt"]
                    order_id = digest(json.dumps(contract_dict, indent=4)).encode("hex")
                    self.send_message(Node(unhexlify(guid)),
                                      contract.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["encryption"],
                                      objects.Plaintext_Message.Type.Value("RECEIPT"),
                                      json.dumps(contract.contract["buyer_receipt"]),
                                      order_id,
                                      store_only=True)
                    return True
                else:
                    return False

            if node_to_ask:
                public_key = contract.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["encryption"]
                skephem = PrivateKey.generate()
                pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                box = Box(skephem, PublicKey(public_key, nacl.encoding.HexEncoder))
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt(json.dumps(contract.contract, indent=4), nonce)
                d = self.protocol.callCompleteOrder(node_to_ask, pkephem, ciphertext)
                return d.addCallback(parse_response)
            else:
                return parse_response([False])
        self.log.info("sending order receipt to %s" % guid)
        return self.kserver.resolve(unhexlify(guid)).addCallback(get_node)

    def open_dispute(self, order_id, claim):
        """
        Given and order ID we will pull the contract from disk and send it along with the claim
        to both the moderator and other party to the dispute. If either party isn't online we will stick
        it in the DHT for them.
        """
        try:
            file_path = DATA_FOLDER + "purchases/in progress" + order_id + ".json"
            with open(file_path, 'r') as filename:
                contract = json.load(filename, object_pairs_hook=OrderedDict)
                guid = contract["vendor_offer"]["listing"]["id"]["guid"]
                enc_key = contract["vendor_offer"]["listing"]["id"]["pubkeys"]["encryption"]
        except Exception:
            try:
                file_path = DATA_FOLDER + "sales/in progress/" + order_id + ".json"
                with open(file_path, 'r') as filename:
                    contract = json.load(filename, object_pairs_hook=OrderedDict)
                    guid = contract["buyer_order"]["order"]["id"]["guid"]
                    enc_key = contract["buyer_order"]["order"]["id"]["pubkeys"]["encryption"]
            except Exception:
                return False
        contract_dict = contract
        if "vendor_order_confirmation" in contract_dict:
            del contract_dict["vendor_order_confirmation"]
        order_id = digest(json.dumps(contract_dict, indent=4)).encode("hex")
        contract["dispute_claim"] = claim
        mod_guid = contract["buyer_order"]["order"]["moderator"]
        for mod in contract["vendor_offer"]["listing"]["moderators"]:
            if mod["guid"] == mod_guid:
                mod_enc_key = mod["pubkeys"]["encryption"]["key"]

        def get_node(node_to_ask, recipient_guid, public_key):
            def parse_response(response):
                if not response[0]:
                    self.send_message(Node(unhexlify(recipient_guid)),
                                      public_key,
                                      objects.Plaintext_Message.Type.Value("DISPUTE"),
                                      contract,
                                      order_id,
                                      store_only=True)

            if node_to_ask:
                skephem = PrivateKey.generate()
                pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                box = Box(skephem, PublicKey(public_key, nacl.encoding.HexEncoder))
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt(json.dumps(contract, indent=4), nonce)
                d = self.protocol.callDisputeOpen(node_to_ask, pkephem, ciphertext)
                return d.addCallback(parse_response)
            else:
                return parse_response([False])

        self.kserver.resolve(unhexlify(guid)).addCallback(get_node, guid, enc_key)
        self.kserver.resolve(unhexlify(mod_guid)).addCallback(get_node, mod_guid, mod_enc_key)


    @staticmethod
    def cache(filename):
        """
        Saves the file to a cache folder if it doesn't already exist.
        """
        if not os.path.isfile(DATA_FOLDER + "cache/" + digest(filename).encode("hex")):
            with open(DATA_FOLDER + "cache/" + digest(filename).encode("hex"), 'wb') as outfile:
                outfile.write(filename)
