__author__ = 'chris'

import base64
import bitcointools
import gnupg
import httplib
import json
import nacl.signing
import nacl.hash
import nacl.encoding
import nacl.utils
import obelisk
import os.path
import pickle
import time
from binascii import unhexlify
from collections import OrderedDict
from config import DATA_FOLDER, TRANSACTION_FEE
from dht.node import Node
from dht.utils import digest
from keys.bip32utils import derive_childkey
from keys.keychain import KeyChain
from log import Logger
from market.contracts import Contract
from market.moderation import process_dispute, close_dispute
from market.profile import Profile
from market.protocol import MarketProtocol
from market.transactions import BitcoinTransaction
from nacl.public import PrivateKey, PublicKey, Box
from protos import objects
from seed import peers
from twisted.internet import defer, reactor, task


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
        task.LoopingCall(self.update_listings).start(3600, now=True)

    def querySeed(self, list_seed_pubkey):
        """
        Query an HTTP seed for known vendors and save the vendors to the db.

        Args:
            Receives a list of one or more tuples Example [(seed, pubkey)]
            seed: A `string` consisting of "ip:port" or "hostname:port"
            pubkey: The hex encoded public key to verify the signature on the response
        """

        for sp in list_seed_pubkey:
            seed, pubkey = sp
            try:
                self.log.debug("querying %s for vendors" % seed)
                c = httplib.HTTPConnection(seed)
                c.request("GET", "/?type=vendors")
                response = c.getresponse()
                self.log.debug("Http response from %s: %s, %s" % (seed, response.status, response.reason))
                data = response.read()
                reread_data = data.decode("zlib")
                proto = peers.PeerSeeds()
                proto.ParseFromString(reread_data)
                verify_key = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.HexEncoder)
                verify_key.verify("".join(proto.serializedNode), proto.signature)
                for peer in proto.serializedNode:
                    try:
                        n = objects.Node()
                        n.ParseFromString(peer)
                        self.db.vendors.save_vendor(n.guid.encode("hex"), peer)
                    except Exception:
                        pass
            except Exception, e:
                self.log.error("failed to query seed: %s" % str(e))

    def get_contract(self, node_to_ask, contract_id):
        """
        Will query the given node to fetch a contract given its hash.
        If the returned contract doesn't have the same hash, it will return None.

        After acquiring the contract it will download all the associated images if it
        does not already have them in cache.

        Args:
            node_to_ask: a `dht.node.Node` object containing an ip and port
            contract_id: a 20 byte hash in raw byte format
        """

        def get_result(result):
            try:
                if result[0]:
                    contract = json.loads(result[1][0], object_pairs_hook=OrderedDict)
                    id_in_contract = contract["vendor_offer"]["listing"]["contract_id"]

                    if id_in_contract != contract_id.encode("hex"):
                        raise Exception("Contract ID doesn't match")

                    # TODO: verify the guid in the contract matches this node's guid
                    signature = contract["vendor_offer"]["signatures"]["guid"]
                    verify_obj = json.dumps(contract["vendor_offer"]["listing"], indent=4)

                    verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                    verify_key.verify(verify_obj, base64.b64decode(signature))

                    bitcoin_key = contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
                    bitcoin_sig = contract["vendor_offer"]["signatures"]["bitcoin"]
                    valid = bitcointools.ecdsa_raw_verify(verify_obj, bitcointools.decode_sig(bitcoin_sig),
                                                          bitcoin_key)
                    if not valid:
                        raise Exception("Invalid Bitcoin signature")

                    if "moderators" in contract["vendor_offer"]["listing"]:
                        for moderator in contract["vendor_offer"]["listing"]["moderators"]:
                            guid = moderator["guid"]
                            guid_key = moderator["pubkeys"]["guid"]
                            bitcoin_key = moderator["pubkeys"]["bitcoin"]["key"]
                            bitcoin_sig = base64.b64decode(moderator["pubkeys"]["bitcoin"]["signature"])
                            h = nacl.hash.sha512(unhexlify(guid_key))
                            pow_hash = h[40:]
                            if int(pow_hash[:6], 16) >= 50 or guid != h[:40]:
                                raise Exception('Invalid GUID')
                            verify_key = nacl.signing.VerifyKey(guid_key, encoder=nacl.encoding.HexEncoder)
                            verify_key.verify(unhexlify(bitcoin_key), bitcoin_sig)
                            #TODO: should probably also validate the handle here.
                    self.cache(result[1][0], id_in_contract)
                    if "image_hashes" in contract["vendor_offer"]["listing"]["item"]:
                        for image_hash in contract["vendor_offer"]["listing"]["item"]["image_hashes"]:
                            self.get_image(node_to_ask, unhexlify(image_hash))
                    return contract
                else:
                    self.log.warning("Fetched an invalid contract from %s" % node_to_ask.id.encode("hex"))
                    return None
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        self.log.info("fetching contract %s from %s" % (contract_id.encode("hex"), node_to_ask))
        d = self.protocol.callGetContract(node_to_ask, contract_id)
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
                    self.cache(result[1][0], digest(result[1][0]).encode("hex"))
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
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(result[1][0], result[1][1])
                p = objects.Profile()
                p.ParseFromString(result[1][0])
                if p.pgp_key.public_key:
                    gpg = gnupg.GPG()
                    gpg.import_keys(p.pgp_key.publicKey)
                    if not gpg.verify(p.pgp_key.signature) or \
                                    node_to_ask.id.encode('hex') not in p.pgp_key.signature:
                        p.ClearField("pgp_key")
                if not os.path.isfile(os.path.join(DATA_FOLDER, 'cache', p.avatar_hash.encode("hex"))):
                    self.get_image(node_to_ask, p.avatar_hash)
                if not os.path.isfile(os.path.join(DATA_FOLDER, 'cache', p.header_hash.encode("hex"))):
                    self.get_image(node_to_ask, p.header_hash)
                self.cache(result[1][0], node_to_ask.id.encode("hex"))
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
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(result[1][0], result[1][1])
                m = objects.Metadata()
                m.ParseFromString(result[1][0])
                if not os.path.isfile(os.path.join(DATA_FOLDER, 'cache', m.avatar_hash.encode("hex"))):
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
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(result[1][0], result[1][1])
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
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(result[1][0], result[1][1])
                l = objects.Listings().ListingMetadata()
                l.ParseFromString(result[1][0])
                if l.thumbnail_hash != "":
                    if not os.path.isfile(os.path.join(DATA_FOLDER, 'cache', l.thumbnail_hash.encode("hex"))):
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
        k.public_key = unhexlify(bitcointools.bip32_extract_key(KeyChain(self.db).bitcoin_master_pubkey))
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
                    u.pubkey = node_to_follow.pubkey
                    m = objects.Metadata()
                    m.ParseFromString(result[1][1])
                    u.metadata.MergeFrom(m)
                    u.signature = result[1][2]
                    verify_key = nacl.signing.VerifyKey(node_to_follow.pubkey)
                    verify_key.verify(result[1][1], result[1][2])
                    self.db.follow.follow(u)
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
        m.short_description = proto.short_description
        m.nsfw = proto.nsfw
        f = objects.Followers.Follower()
        f.guid = self.kserver.node.id
        f.following = node_to_follow.id
        f.pubkey = self.kserver.node.pubkey
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
                    self.db.follow.unfollow(node_to_unfollow.id)
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
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(response[1][0], response[1][1])
                f.ParseFromString(response[1][0])
            except Exception:
                return None
            # Verify the signature and guid of each follower.
            for follower in f.followers:
                try:
                    v_key = nacl.signing.VerifyKey(follower.pubkey)
                    signature = follower.signature
                    follower.ClearField("signature")
                    v_key.verify(follower.SerializeToString(), signature)
                    h = nacl.hash.sha512(follower.pubkey)
                    pow_hash = h[40:]
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
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(response[1][0], response[1][1])
                f.ParseFromString(response[1][0])
            except Exception:
                return None
            for user in f.users:
                try:
                    v_key = nacl.signing.VerifyKey(user.pubkey)
                    signature = user.signature
                    v_key.verify(user.metadata.SerializeToString(), signature)
                    h = nacl.hash.sha512(user.pubkey)
                    pow_hash = h[40:]
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
        f.ParseFromString(self.db.follow.get_followers())
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
        p = objects.PlaintextMessage()
        p.sender_guid = self.kserver.node.id
        p.pubkey = self.kserver.node.pubkey
        p.type = message_type
        p.message = str(message)
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
        box = Box(skephem, PublicKey(public_key))
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
                            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(value.valueKey))
                            ciphertext = value.serializedData
                            plaintext = box.decrypt(ciphertext).decode("zlib")
                            p = objects.PlaintextMessage()
                            p.ParseFromString(plaintext)
                            signature = p.signature
                            p.ClearField("signature")
                            verify_key = nacl.signing.VerifyKey(p.pubkey)
                            verify_key.verify(p.SerializeToString(), signature)
                            h = nacl.hash.sha512(p.pubkey)
                            pow_hash = h[40:]
                            if int(pow_hash[:6], 16) >= 50 or p.sender_guid.encode("hex") != h[:40]:
                                raise Exception('Invalid guid')
                            if p.type == objects.PlaintextMessage.Type.Value("ORDER_CONFIRMATION"):
                                c = Contract(self.db, hash_value=unhexlify(p.subject),
                                             testnet=self.protocol.multiplexer.testnet)
                                c.accept_order_confirmation(self.protocol.get_notification_listener(),
                                                            confirmation_json=p.message)
                            elif p.type == objects.PlaintextMessage.Type.Value("RECEIPT"):
                                c = Contract(self.db, hash_value=unhexlify(p.subject),
                                             testnet=self.protocol.multiplexer.testnet)
                                c.accept_receipt(self.protocol.get_notification_listener(),
                                                 self.protocol.multiplexer.blockchain,
                                                 receipt_json=p.message)
                            elif p.type == objects.PlaintextMessage.Type.Value("DISPUTE_OPEN"):
                                process_dispute(json.loads(p.message, object_pairs_hook=OrderedDict),
                                                self.db, self.protocol.get_message_listener(),
                                                self.protocol.get_notification_listener(),
                                                self.protocol.multiplexer.testnet)
                            elif p.type == objects.PlaintextMessage.Type.Value("DISPUTE_CLOSE"):
                                close_dispute(json.loads(p.message, object_pairs_hook=OrderedDict),
                                              self.db, self.protocol.get_message_listener(),
                                              self.protocol.get_notification_listener(),
                                              self.protocol.multiplexer.testnet)
                            elif p.type == objects.PlaintextMessage.Type.Value("REFUND"):
                                refund_json = json.loads(p.message, object_pairs_hook=OrderedDict)
                                c = Contract(self.db, hash_value=unhexlify(refund_json["refund"]["order_id"]),
                                             testnet=self.protocol.multiplexer.testnet)
                                c.process_refund(refund_json, self.protocol.multiplexer.blockchain,
                                                 self.protocol.get_notification_listener())
                            else:
                                listener.notify(p, signature)
                        except Exception:
                            pass
                        signature = self.signing_key.sign(value.valueKey)[:64]
                        self.kserver.delete(self.kserver.node.id, value.valueKey, signature)
                    except Exception:
                        pass
        self.kserver.get(self.kserver.node.id, False).addCallback(parse_messages)

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
                listing_hash = contract.contract["vendor_offer"]["listing"]["contract_id"]
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(
                    str(address) + str(amount) + str(listing_hash) + str(buyer_key), response[1][0])
                return response[1][0]
            except Exception:
                return False

        public_key = nacl.signing.VerifyKey(contract.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["guid"],
                                            encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        skephem = PrivateKey.generate()
        pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
        box = Box(skephem, public_key)
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        ciphertext = box.encrypt(json.dumps(contract.contract, indent=4), nonce)
        d = self.protocol.callOrder(node_to_ask, pkephem, ciphertext)
        self.log.info("purchasing contract %s from %s" % (contract.get_contract_id(), node_to_ask))
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
                                      nacl.signing.VerifyKey(
                                          contract.contract["buyer_order"]["order"]["id"]["pubkeys"]["guid"],
                                          encoder=nacl.encoding.HexEncoder).to_curve25519_public_key().encode(),
                                      objects.PlaintextMessage.Type.Value("ORDER_CONFIRMATION"),
                                      json.dumps(contract.contract["vendor_order_confirmation"]),
                                      order_id,
                                      store_only=True)
                    return True
                else:
                    return response[1][0]

            if node_to_ask:
                public_key = nacl.signing.VerifyKey(
                    contract.contract["buyer_order"]["order"]["id"]["pubkeys"]["guid"],
                    encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
                skephem = PrivateKey.generate()
                pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                box = Box(skephem, public_key)
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
                                      nacl.signing.VerifyKey(
                                          contract.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["guid"],
                                          encoder=nacl.encoding.HexEncoder).to_curve25519_public_key().encode(),
                                      objects.PlaintextMessage.Type.Value("RECEIPT"),
                                      json.dumps(contract.contract["buyer_receipt"]),
                                      order_id,
                                      store_only=True)
                    return True
                else:
                    return response[1][0]

            if node_to_ask:
                public_key = nacl.signing.VerifyKey(
                    contract.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["guid"],
                    encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
                skephem = PrivateKey.generate()
                pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                box = Box(skephem, public_key)
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
            file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", order_id + ".json")
            with open(file_path, 'r') as filename:
                contract = json.load(filename, object_pairs_hook=OrderedDict)
                guid = contract["vendor_offer"]["listing"]["id"]["guid"]
                handle = ""
                if "blockchain_id" in contract["vendor_offer"]["listing"]["id"]:
                    handle = contract["vendor_offer"]["listing"]["id"]["blockchain_id"]
                guid_key = contract["vendor_offer"]["listing"]["id"]["pubkeys"]["guid"]
                proof_sig = self.db.purchases.get_proof_sig(order_id)
        except Exception:
            try:
                file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", order_id + ".json")
                with open(file_path, 'r') as filename:
                    contract = json.load(filename, object_pairs_hook=OrderedDict)
                    guid = contract["buyer_order"]["order"]["id"]["guid"]
                    handle = ""
                    if "blockchain_id" in contract["buyer_order"]["order"]["id"]:
                        handle = contract["buyer_order"]["order"]["id"]["blockchain_id"]
                    guid_key = contract["buyer_order"]["order"]["id"]["pubkeys"]["guid"]
                    proof_sig = None
            except Exception:
                return False

        if "dispute" not in contract:
            keychain = KeyChain(self.db)
            contract["dispute"] = {}
            contract["dispute"]["info"] = {}
            contract["dispute"]["info"]["claim"] = claim
            contract["dispute"]["info"]["guid"] = keychain.guid.encode("hex")
            contract["dispute"]["info"]["avatar_hash"] = Profile(self.db).get().avatar_hash.encode("hex")
            if proof_sig:
                contract["dispute"]["info"]["proof_sig"] = base64.b64encode(proof_sig)
            info = json.dumps(contract["dispute"]["info"], indent=4)
            contract["dispute"]["signature"] = base64.b64encode(keychain.signing_key.sign(info)[:64])
            with open(file_path, 'wb') as outfile:
                outfile.write(json.dumps(contract, indent=4))

            if self.db.purchases.get_purchase(order_id) is not None:
                self.db.purchases.update_status(order_id, 4)

            elif self.db.sales.get_sale(order_id) is not None:
                self.db.sales.update_status(order_id, 4)

            avatar_hash = Profile(self.db).get().avatar_hash

            self.db.messages.save_message(guid, handle, "", order_id, "DISPUTE_OPEN",
                                          claim, time.time(), avatar_hash, "", True)

        mod_guid = contract["buyer_order"]["order"]["moderator"]
        for mod in contract["vendor_offer"]["listing"]["moderators"]:
            if mod["guid"] == mod_guid:
                mod_key = mod["pubkeys"]["guid"]

        def get_node(node_to_ask, recipient_guid, public_key):
            def parse_response(response):
                if not response[0]:
                    self.send_message(Node(unhexlify(recipient_guid)),
                                      nacl.signing.VerifyKey(
                                          public_key,
                                          encoder=nacl.encoding.HexEncoder).to_curve25519_public_key().encode(),
                                      objects.PlaintextMessage.Type.Value("DISPUTE_OPEN"),
                                      json.dumps(contract),
                                      order_id,
                                      store_only=True)

            if node_to_ask:
                enc_key = nacl.signing.VerifyKey(
                    public_key, encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
                skephem = PrivateKey.generate()
                pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                box = Box(skephem, enc_key)
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt(json.dumps(contract, indent=4), nonce)
                d = self.protocol.callDisputeOpen(node_to_ask, pkephem, ciphertext)
                return d.addCallback(parse_response)
            else:
                return parse_response([False])

        self.kserver.resolve(unhexlify(guid)).addCallback(get_node, guid, guid_key)
        self.kserver.resolve(unhexlify(mod_guid)).addCallback(get_node, mod_guid, mod_key)

    def close_dispute(self, order_id, resolution, buyer_percentage,
                      vendor_percentage, moderator_percentage, moderator_address):
        """
        Called when a moderator closes a dispute. It will create a payout transactions refunding both
        parties and send it to them in a dispute_close message.
        """
        if float(vendor_percentage) < 0 or float(moderator_percentage) < 0 or float(buyer_percentage) < 0:
            raise Exception("Payouts percentages must be positive")
        if float(vendor_percentage) + float(buyer_percentage) > 1:
            raise Exception("Payout exceeds 100% of value")
        if not self.protocol.multiplexer.blockchain.connected:
            raise Exception("Libbitcoin server not online")
        if not self.protocol.multiplexer.testnet and \
                not (moderator_address[:1] == "1" or moderator_address[:1] == "3"):
            raise Exception("Bitcoin address is not a mainnet address")
        elif self.protocol.multiplexer.testnet and not \
                (moderator_address[:1] == "n" or moderator_address[:1] == "m" or moderator_address[:1] == "2"):
            raise Exception("Bitcoin address is not a testnet address")
        try:
            bitcointools.b58check_to_hex(moderator_address)
        except AssertionError:
            raise Exception("Invalid Bitcoin address")

        with open(os.path.join(DATA_FOLDER, "cases", order_id + ".json"), "r") as filename:
            contract = json.load(filename, object_pairs_hook=OrderedDict)

        buyer_address = contract["buyer_order"]["order"]["refund_address"]

        buyer_guid = contract["buyer_order"]["order"]["id"]["guid"]
        buyer_enc_key = nacl.signing.VerifyKey(
            contract["buyer_order"]["order"]["id"]["pubkeys"]["guid"],
            encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        vendor_guid = contract["vendor_offer"]["listing"]["id"]["guid"]
        vendor_enc_key = nacl.signing.VerifyKey(
            contract["vendor_offer"]["listing"]["id"]["pubkeys"]["guid"],
            encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()

        payment_address = contract["buyer_order"]["order"]["payment"]["address"]

        def history_fetched(ec, history):
            outpoints = []
            satoshis = 0
            outputs = []
            dispute_json = {"dispute_resolution": {"resolution": {}}}
            timeout.cancel()
            if ec:
                print ec
            else:
                for tx_type, txid, i, height, value in history:  # pylint: disable=W0612
                    if tx_type == obelisk.PointIdent.Output:
                        satoshis += value
                        o = {
                            "txid": txid.encode("hex"),
                            "vout": i,
                            "value": value,
                            "scriptPubKey": "00"
                        }
                        if o not in outpoints:
                            outpoints.append(o)

                if satoshis <= 0:
                    d.callback(False)
                else:
                    satoshis -= TRANSACTION_FEE
                    moderator_fee = int(float(moderator_percentage) * satoshis)
                    satoshis -= moderator_fee

                    if moderator_fee > 0:
                        outputs.append({'value': moderator_fee, 'address': moderator_address})
                    dispute_json["dispute_resolution"]["resolution"]["moderator_address"] = moderator_address
                    dispute_json["dispute_resolution"]["resolution"]["moderator_fee"] = \
                        round(moderator_fee / float(100000000), 8)
                    dispute_json["dispute_resolution"]["resolution"]["transaction_fee"] = \
                        round(TRANSACTION_FEE / float(100000000), 8)
                    if float(buyer_percentage) > 0:
                        amt = int(float(buyer_percentage) * satoshis)
                        dispute_json["dispute_resolution"]["resolution"]["buyer_payout"] = \
                            round(amt / float(100000000), 8)
                        outputs.append({'value': amt,
                                        'address': buyer_address})
                    if float(vendor_percentage) > 0:
                        amt = int(float(vendor_percentage) * satoshis)
                        dispute_json["dispute_resolution"]["resolution"]["vendor_payout"] = \
                            round(amt / float(100000000), 8)
                        outputs.append({'value': amt,
                                        'address': vendor_address})

                    tx = BitcoinTransaction.make_unsigned(outpoints, outputs,
                                                          testnet=self.protocol.multiplexer.testnet)
                    chaincode = contract["buyer_order"]["order"]["payment"]["chaincode"]
                    redeem_script = str(contract["buyer_order"]["order"]["payment"]["redeem_script"])
                    masterkey_m = bitcointools.bip32_extract_key(KeyChain(self.db).bitcoin_master_privkey)
                    moderator_priv = derive_childkey(masterkey_m, chaincode, bitcointools.MAINNET_PRIVATE)

                    signatures = tx.create_signature(moderator_priv, redeem_script)
                    dispute_json["dispute_resolution"]["resolution"]["order_id"] = order_id
                    dispute_json["dispute_resolution"]["resolution"]["tx_signatures"] = signatures
                    dispute_json["dispute_resolution"]["resolution"]["claim"] = self.db.cases.get_claim(order_id)
                    dispute_json["dispute_resolution"]["resolution"]["decision"] = resolution
                    dispute_json["dispute_resolution"]["signature"] = \
                        base64.b64encode(KeyChain(self.db).signing_key.sign(json.dumps(
                            dispute_json["dispute_resolution"]["resolution"], indent=4))[:64])

                    contract["dispute_resolution"] = dispute_json["dispute_resolution"]
                    with open(DATA_FOLDER + "cases/" + order_id + ".json", 'wb') as outfile:
                        outfile.write(json.dumps(contract, indent=4))

                    send(dispute_json)

        def send(dispute_json):
            def get_node(node_to_ask, recipient_guid, public_key):
                def parse_response(response):
                    if not response[0]:
                        self.send_message(Node(unhexlify(recipient_guid)),
                                          public_key.encode(),
                                          objects.PlaintextMessage.Type.Value("DISPUTE_CLOSE"),
                                          dispute_json,
                                          order_id,
                                          store_only=True)

                if node_to_ask:
                    skephem = PrivateKey.generate()
                    pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                    box = Box(skephem, public_key)
                    nonce = nacl.utils.random(Box.NONCE_SIZE)
                    ciphertext = box.encrypt(json.dumps(dispute_json, indent=4), nonce)
                    self.protocol.callDisputeClose(node_to_ask, pkephem, ciphertext).addCallback(parse_response)
                else:
                    parse_response([False])

            self.kserver.resolve(unhexlify(vendor_guid)).addCallback(get_node, vendor_guid, vendor_enc_key)
            self.kserver.resolve(unhexlify(buyer_guid)).addCallback(get_node, buyer_guid, buyer_enc_key)
            self.db.cases.update_status(order_id, 1)
            d.callback(True)

        d = defer.Deferred()

        if "dispute_resolution" not in contract:
            if "vendor_order_confirmation" in contract and float(vendor_percentage) > 0:
                vendor_address = contract["vendor_order_confirmation"]["invoice"]["payout"]["address"]
            elif "vendor_order_confirmation" not in contract and float(vendor_percentage) > 0:
                raise Exception("Cannot refund seller before order confirmation is sent")

            def libbitcoin_timeout():
                d.callback("timed out")

            timeout = reactor.callLater(5, libbitcoin_timeout)
            self.protocol.multiplexer.blockchain.fetch_history2(payment_address, history_fetched)
        else:
            dispute_json = {"dispute_resolution": contract["dispute_resolution"]}
            send(dispute_json)
        return d

    def release_funds(self, order_id):
        """
        This function should be called to release funds from a disputed contract after
        the moderator has resolved the dispute and provided his signature.
        """
        if os.path.exists(os.path.join(DATA_FOLDER, "purchases", "in progress", order_id + ".json")):
            file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", order_id + ".json")
            outpoints = json.loads(self.db.purchases.get_outpoint(order_id))
        elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "in progress", order_id + ".json")):
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", order_id + ".json")
            outpoints = json.loads(self.db.sales.get_outpoint(order_id))

        with open(file_path, 'r') as filename:
            contract = json.load(filename, object_pairs_hook=OrderedDict)

        outputs = []

        moderator_fee = int(round(float(contract["dispute_resolution"]
                                        ["resolution"]["moderator_fee"]) * 100000000))
        if moderator_fee > 0:
            outputs.append({'value': moderator_fee,
                            'address': contract["dispute_resolution"]["resolution"]["moderator_address"]})

        if "buyer_payout" in contract["dispute_resolution"]["resolution"]:
            buyer_address = contract["buyer_order"]["order"]["refund_address"]
            outputs.append({'value': int(round(float(contract["dispute_resolution"]
                                                     ["resolution"]["buyer_payout"]) * 100000000)),
                            'address': buyer_address})

        if "vendor_payout" in contract["dispute_resolution"]["resolution"]:
            vendor_address = contract["vendor_order_confirmation"]["invoice"]["payout"]["address"]
            outputs.append({'value': int(round(float(contract["dispute_resolution"]
                                                     ["resolution"]["vendor_payout"]) * 100000000)),
                            'address': vendor_address})

        tx = BitcoinTransaction.make_unsigned(outpoints, outputs, testnet=self.protocol.multiplexer.testnet)
        chaincode = contract["buyer_order"]["order"]["payment"]["chaincode"]
        redeem_script = str(contract["buyer_order"]["order"]["payment"]["redeem_script"])
        masterkey = bitcointools.bip32_extract_key(KeyChain(self.db).bitcoin_master_privkey)
        childkey = derive_childkey(masterkey, chaincode, bitcointools.MAINNET_PRIVATE)

        own_sig = tx.create_signature(childkey, redeem_script)

        signatures = []
        for index in range(0, len(outpoints)):
            sig_ob = {"index": index, "signatures": []}
            for s in own_sig:
                if int(s["index"]) == index:
                    sig_ob["signatures"].append(s["signature"])
            for s in contract["dispute_resolution"]["resolution"]["tx_signatures"]:
                if int(s["index"]) == index:
                    sig_ob["signatures"].append(s["signature"])
            signatures.append(sig_ob)

        tx.multisign(signatures, redeem_script)
        tx.broadcast(self.protocol.multiplexer.blockchain)
        self.db.transactions.add_transaction(tx.to_raw_tx())
        self.log.info("broadcasting payout tx %s to network" % tx.get_hash())

        if self.db.purchases.get_purchase(order_id) is not None:
            self.db.purchases.update_status(order_id, 6)
        elif self.db.sales.get_sale(order_id) is not None:
            self.db.sales.update_status(order_id, 6)

    def get_ratings(self, node_to_ask, listing_hash=None):
        """
        Query the given node for a listing of ratings/reviews for the given listing.
        """
        def get_result(result):
            try:
                verify_key = nacl.signing.VerifyKey(node_to_ask.pubkey)
                verify_key.verify(result[1][0], result[1][1])
                ratings = json.loads(result[1][0].decode("zlib"), object_pairs_hook=OrderedDict)
                ret = []
                for rating in ratings:
                    address = rating["tx_summary"]["address"]
                    buyer_key = rating["tx_summary"]["buyer_key"]
                    amount = rating["tx_summary"]["amount"]
                    listing_hash = rating["tx_summary"]["listing"]
                    proof_sig = rating["tx_summary"]["proof_of_tx"]
                    try:
                        verify_key.verify(str(address) + str(amount) + str(listing_hash) + str(buyer_key),
                                          base64.b64decode(proof_sig))

                        valid = bitcointools.ecdsa_raw_verify(json.dumps(rating["tx_summary"], indent=4),
                                                              bitcointools.decode_sig(rating["signature"]),
                                                              buyer_key)
                        if not valid:
                            raise Exception("Bitcoin signature not valid")

                        if "buyer_guid" in rating["tx_summary"] or "buyer_guid_key" in rating["tx_summary"]:
                            buyer_key_bin = unhexlify(rating["tx_summary"]["buyer_guid_key"])
                            buyer_key = nacl.signing.VerifyKey(buyer_key_bin)
                            buyer_key.verify(json.dumps(rating["tx_summary"], indent=4),
                                             base64.b64decode(rating["guid_signature"]))
                            h = nacl.hash.sha512(buyer_key_bin)
                            pow_hash = h[40:]
                            if int(pow_hash[:6], 16) >= 50 or rating["tx_summary"]["buyer_guid"] != h[:40]:
                                raise Exception('Invalid GUID')

                        ret.append(rating)
                    except Exception:
                        pass
                return ret
            except Exception:
                return None

        if node_to_ask.ip is None:
            return defer.succeed(None)
        a = "ALL" if listing_hash is None else listing_hash.encode("hex")
        self.log.info("fetching ratings for contract %s from %s" % (a, node_to_ask))
        d = self.protocol.callGetRatings(node_to_ask, listing_hash)
        return d.addCallback(get_result)

    def refund(self, order_id):
        """
        Refund the given order_id. If this is a direct payment he transaction will be
        immediately broadcast to the Bitcoin network otherwise the refund message sent
        to the buyer with contain the signature.
        """
        file_path = os.path.join(DATA_FOLDER + "store", "contracts", "in progress", order_id + ".json")
        if not os.path.exists(file_path):
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "trade receipts", order_id + ".json")
        outpoints = json.loads(self.db.sales.get_outpoint(order_id))

        with open(file_path, 'r') as filename:
            contract = json.load(filename, object_pairs_hook=OrderedDict)

        buyer_guid = contract["buyer_order"]["order"]["id"]["guid"]
        buyer_enc_key = nacl.signing.VerifyKey(
            contract["buyer_order"]["order"]["id"]["pubkeys"]["guid"],
            encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        if "refund" in contract:
            refund_json = {"refund": contract["refund"]}
        else:
            refund_address = contract["buyer_order"]["order"]["refund_address"]
            chaincode = contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_v = bitcointools.bip32_extract_key(KeyChain(self.db).bitcoin_master_privkey)
            vendor_priv = derive_childkey(masterkey_v, chaincode, bitcointools.MAINNET_PRIVATE)

            refund_json = {"refund": {}}
            refund_json["refund"]["order_id"] = order_id
            if "moderator" in contract["buyer_order"]["order"]:
                in_value = 0
                for outpoint in outpoints:
                    in_value += outpoint["value"]
                out_value = in_value - long(contract["buyer_order"]["order"]["payment"]["refund_tx_fee"])
                tx = BitcoinTransaction.make_unsigned(outpoints, refund_address,
                                                      testnet=self.protocol.multiplexer.testnet,
                                                      out_value=out_value)
                redeem_script = contract["buyer_order"]["order"]["payment"]["redeem_script"]
                sigs = tx.create_signature(vendor_priv, redeem_script)
                refund_json["refund"]["value"] = round(tx.get_out_value() / float(100000000), 8)
                refund_json["refund"]["signature(s)"] = sigs
            else:
                tx = BitcoinTransaction.make_unsigned(outpoints, refund_address,
                                                      testnet=self.protocol.multiplexer.testnet)
                tx.sign(vendor_priv)
                tx.broadcast(self.protocol.multiplexer.blockchain)
                self.db.transactions.add_transaction(tx.to_raw_tx())
                self.log.info("broadcasting refund tx %s to network" % tx.get_hash())
                refund_json["refund"]["txid"] = tx.get_hash()

            contract["refund"] = refund_json["refund"]
            self.db.sales.update_status(order_id, 7)
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "trade receipts", order_id + ".json")
            with open(file_path, 'w') as outfile:
                outfile.write(json.dumps(contract, indent=4))
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", order_id + ".json")
            if os.path.exists(file_path):
                os.remove(file_path)

        def get_node(node_to_ask):
            def parse_response(response):
                if response[0] and response[1][0] == "True":
                    return True
                if not response[0]:
                    self.send_message(Node(unhexlify(buyer_guid)),
                                      buyer_enc_key.encode(),
                                      objects.PlaintextMessage.Type.Value("REFUND"),
                                      refund_json,
                                      order_id,
                                      store_only=True)
                    return True
                else:
                    return response[1][0]

            if node_to_ask:
                skephem = PrivateKey.generate()
                pkephem = skephem.public_key.encode(nacl.encoding.RawEncoder)
                box = Box(skephem, buyer_enc_key)
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                ciphertext = box.encrypt(json.dumps(refund_json, indent=4), nonce)
                d = self.protocol.callRefund(node_to_ask, pkephem, ciphertext)
                return d.addCallback(parse_response)
            else:
                return parse_response([False])

        self.log.info("sending refund message to %s" % buyer_guid)
        return self.kserver.resolve(unhexlify(buyer_guid)).addCallback(get_node)

    def update_listings(self):
        try:
            if self.protocol.multiplexer is None:
                return reactor.callLater(1, self.update_listings)
            fname = os.path.join(DATA_FOLDER, "store", "listings.pickle")
            if os.path.exists(fname):
                with open(fname, 'r') as f:
                    data = pickle.load(f)
            else:
                data = {}

            l = objects.Listings()
            l.ParseFromString(self.db.listings.get_proto())
            for listing in l.listing:
                contract_hash = listing.contract_hash
                c = Contract(self.db, hash_value=contract_hash, testnet=self.protocol.multiplexer.testnet)
                if contract_hash not in data or time.time() - data[contract_hash] > 500000:
                    for keyword in c.contract["vendor_offer"]["listing"]["item"]["keywords"]:
                        self.kserver.set(digest(keyword.lower()), unhexlify(c.get_contract_id()),
                                         self.kserver.node.getProto().SerializeToString())
                    data[contract_hash] = time.time()
                if c.check_expired():
                    c.delete(True)
                    if contract_hash in data:
                        del data[contract_hash]
            guid = KeyChain(self.db).guid
            moderator = Profile(self.db).get().moderator
            if (guid not in data or time.time() - data[guid] > 500000) and moderator:
                self.make_moderator()
                data[guid] = time.time()
            with open(fname, 'w') as f:
                pickle.dump(data, f)
        except Exception:
            pass

    def update_moderators_on_listings(self, moderator_list):
        try:
            l = objects.Listings()
            l.ParseFromString(self.db.listings.get_proto())
        except Exception:
            return
        keychain = KeyChain(self.db)
        for listing in l.listing:
            try:
                contract_hash = listing.contract_hash
                c = Contract(self.db, hash_value=contract_hash, testnet=self.protocol.multiplexer.testnet)
                contract_moderators = []
                if "moderators" in c.contract["vendor_offer"]["listing"]:
                    for m in c.contract["vendor_offer"]["listing"]["moderators"]:
                        contract_moderators.append(m["guid"])
                mods_to_remove = list(set(contract_moderators) - set(moderator_list))
                mods_to_add = list(set(moderator_list) - set(contract_moderators))
                for mod in mods_to_add:
                    mod_info = self.db.moderators.get_moderator(mod)
                    if mod_info is not None:
                        moderator_json = {
                            "guid": mod,
                            "name": mod_info[5],
                            "avatar": mod_info[7].encode("hex"),
                            "short_description": mod_info[6],
                            "fee": str(mod_info[8]) + "%",
                            "blockchain_id": mod_info[4],
                            "pubkeys": {
                                "guid": mod_info[1].encode("hex"),
                                "bitcoin": {
                                    "key": mod_info[2].encode("hex"),
                                    "signature": base64.b64encode(mod_info[3])
                                }
                            }
                        }
                        if "moderators" not in c.contract["vendor_offer"]["listing"]:
                            c.contract["vendor_offer"]["listing"]["moderators"] = []
                        c.contract["vendor_offer"]["listing"]["moderators"].append(moderator_json)
                for mod in mods_to_remove:
                    for rem in c.contract["vendor_offer"]["listing"]["moderators"]:
                        if rem["guid"] == mod:
                            c.contract["vendor_offer"]["listing"]["moderators"].remove(rem)
                if "moderators" in c.contract["vendor_offer"]["listing"] and \
                                len(c.contract["vendor_offer"]["listing"]["moderators"]) == 0:
                    del c.contract["vendor_offer"]["listing"]["moderators"]

                listing = json.dumps(c.contract["vendor_offer"]["listing"], indent=4)
                c.contract["vendor_offer"]["signatures"] = {}
                c.contract["vendor_offer"]["signatures"]["guid"] = \
                    base64.b64encode(keychain.signing_key.sign(listing)[:64])
                c.contract["vendor_offer"]["signatures"]["bitcoin"] = \
                    bitcointools.encode_sig(*bitcointools.ecdsa_raw_sign(
                        listing, bitcointools.bip32_extract_key(keychain.bitcoin_master_privkey)))
                c.previous_title = None
                c.save()
            except Exception:
                pass

    @staticmethod
    def cache(file_to_save, filename):
        """
        Saves the file to a cache folder override previous versions if any.
        """
        with open(os.path.join(DATA_FOLDER, "cache", filename), 'wb') as outfile:
            outfile.write(file_to_save)
