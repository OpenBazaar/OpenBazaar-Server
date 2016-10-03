__author__ = 'chris'

import json
import nacl.signing
import nacl.utils
import nacl.encoding
import nacl.hash
from binascii import unhexlify
from collections import OrderedDict
from interfaces import MessageProcessor, BroadcastListener, MessageListener, NotificationListener
from keys.bip32utils import derive_childkey
from log import Logger
from market.audit import Audit
from market.contracts import Contract
from market.moderation import process_dispute, close_dispute
from market.profile import Profile
from market.smtpnotification import SMTPNotification
from nacl.public import PublicKey, Box
from net.rpcudp import RPCProtocol
from protos.message import GET_CONTRACT, GET_IMAGE, GET_PROFILE, GET_LISTINGS, GET_USER_METADATA,\
    GET_CONTRACT_METADATA, FOLLOW, UNFOLLOW, GET_FOLLOWERS, GET_FOLLOWING, BROADCAST, MESSAGE, ORDER, \
    ORDER_CONFIRMATION, COMPLETE_ORDER, DISPUTE_OPEN, DISPUTE_CLOSE, GET_RATINGS, REFUND
from protos.objects import Metadata, Listings, Followers, PlaintextMessage
from zope.interface import implements
from zope.interface.exceptions import DoesNotImplement
from zope.interface.verify import verifyObject


class MarketProtocol(RPCProtocol):
    implements(MessageProcessor)

    def __init__(self, node, router, signing_key, database):
        self.router = router
        self.node = node
        RPCProtocol.__init__(self, node, router)
        self.log = Logger(system=self)
        self.audit = Audit(db=database)
        self.multiplexer = None
        self.db = database
        self.signing_key = signing_key
        self.listeners = []
        self.handled_commands = [GET_CONTRACT, GET_IMAGE, GET_PROFILE, GET_LISTINGS, GET_USER_METADATA,
                                 GET_CONTRACT_METADATA, FOLLOW, UNFOLLOW, GET_FOLLOWERS, GET_FOLLOWING,
                                 BROADCAST, MESSAGE, ORDER, ORDER_CONFIRMATION, COMPLETE_ORDER, DISPUTE_OPEN,
                                 DISPUTE_CLOSE, GET_RATINGS, REFUND]

    def connect_multiplexer(self, multiplexer):
        self.multiplexer = multiplexer

    def add_listener(self, listener):
        self.listeners.append(listener)

    def rpc_get_contract(self, sender, contract_hash):
        self.log.info("serving contract %s to %s" % (contract_hash.encode('hex'), sender))
        self.audit.record(sender.id.encode("hex"), "GET_CONTRACT", contract_hash.encode('hex'))
        self.router.addContact(sender)
        try:
            with open(self.db.filemap.get_file(contract_hash.encode("hex")), "r") as filename:
                contract = filename.read()
            return [contract]
        except Exception:
            self.log.warning("could not find contract %s" % contract_hash.encode('hex'))
            return None

    def rpc_get_image(self, sender, image_hash):
        self.router.addContact(sender)
        try:
            if len(image_hash) != 20:
                self.log.warning("Image hash is not 20 characters %s" % image_hash)
                raise Exception("Invalid image hash")
            self.log.info("serving image %s to %s" % (image_hash.encode('hex'), sender))
            with open(self.db.filemap.get_file(image_hash.encode("hex")), "rb") as filename:
                image = filename.read()
            return [image]
        except Exception:
            self.log.warning("could not find image %s" % image_hash[:20].encode('hex'))
            return None

    def rpc_get_profile(self, sender):
        self.log.info("serving profile to %s" % sender)
        self.audit.record(sender.id.encode("hex"), "GET_PROFILE")
        self.router.addContact(sender)
        try:
            proto = Profile(self.db).get(True)
            return [proto, self.signing_key.sign(proto)[:64]]
        except Exception:
            self.log.error("unable to load the profile")
            return None

    def rpc_get_user_metadata(self, sender):
        self.log.info("serving user metadata to %s" % sender)
        self.router.addContact(sender)
        try:
            proto = Profile(self.db).get(False)
            m = Metadata()
            m.name = proto.name
            m.handle = proto.handle
            m.short_description = proto.short_description
            m.avatar_hash = proto.avatar_hash
            m.nsfw = proto.nsfw
            return [m.SerializeToString(), self.signing_key.sign(m.SerializeToString())[:64]]
        except Exception:
            self.log.error("unable to load profile metadata")
            return None

    def rpc_get_listings(self, sender):
        self.log.info("serving store listings to %s" % sender)
        self.audit.record(sender.id.encode("hex"), "GET_LISTINGS")
        self.router.addContact(sender)
        try:
            p = Profile(self.db).get()
            l = Listings()
            l.ParseFromString(self.db.listings.get_proto())
            l.handle = p.handle
            l.avatar_hash = p.avatar_hash
            for listing in l.listing:
                if listing.hidden:
                    l.listing.remove(listing)
            return [l.SerializeToString(), self.signing_key.sign(l.SerializeToString())[:64]]
        except Exception:
            self.log.warning("could not find any listings in the database")
            return None

    def rpc_get_contract_metadata(self, sender, contract_hash):
        self.log.info("serving metadata for contract %s to %s" % (contract_hash.encode("hex"), sender))
        self.router.addContact(sender)
        try:
            proto = self.db.listings.get_proto()
            p = Profile(self.db).get()
            l = Listings()
            l.ParseFromString(proto)
            for listing in l.listing:
                if listing.contract_hash == contract_hash:
                    listing.avatar_hash = p.avatar_hash
                    listing.handle = p.handle
                    ser = listing.SerializeToString()
            return [ser, self.signing_key.sign(ser)[:64]]
        except Exception:
            self.log.warning("could not find metadata for contract %s" % contract_hash.encode("hex"))
            return None

    def rpc_follow(self, sender, proto, signature):
        self.log.info("received follow request from %s" % sender)
        self.router.addContact(sender)
        try:
            verify_key = nacl.signing.VerifyKey(sender.pubkey)
            verify_key.verify(proto, signature)
            f = Followers.Follower()
            f.ParseFromString(proto)
            if f.guid != sender.id:
                raise Exception('GUID does not match sending node')
            if f.following != self.node.id:
                raise Exception('Following wrong node')
            f.signature = signature
            self.db.follow.set_follower(f.SerializeToString())
            proto = Profile(self.db).get(False)
            m = Metadata()
            m.name = proto.name
            m.handle = proto.handle
            m.avatar_hash = proto.avatar_hash
            m.short_description = proto.short_description
            m.nsfw = proto.nsfw
            for listener in self.listeners:
                try:
                    verifyObject(NotificationListener, listener)
                    listener.notify(sender.id, f.metadata.handle, "follow", "", "", f.metadata.avatar_hash)
                except DoesNotImplement:
                    pass

            # Send SMTP notification
            notification = SMTPNotification(self.db)
            notification.send("[OpenBazaar] %s is now following you!" % f.metadata.name,
                              "You have a new follower:<br><br>Name: %s<br>GUID: <a href=\"ob://%s\">%s</a><br>"
                              "Handle: %s" %
                              (f.metadata.name, f.guid.encode('hex'), f.guid.encode('hex'), f.metadata.handle))

            return ["True", m.SerializeToString(), self.signing_key.sign(m.SerializeToString())[:64]]
        except Exception:
            self.log.warning("failed to validate follower")
            return ["False"]

    def rpc_unfollow(self, sender, signature):
        self.log.info("received unfollow request from %s" % sender)
        self.router.addContact(sender)
        try:
            verify_key = nacl.signing.VerifyKey(sender.pubkey)
            verify_key.verify("unfollow:" + self.node.id, signature)
            f = self.db.follow
            f.delete_follower(sender.id)
            return ["True"]
        except Exception:
            self.log.warning("failed to validate signature on unfollow request")
            return ["False"]

    def rpc_get_followers(self, sender, start=None):
        self.log.info("serving followers list to %s" % sender)
        self.audit.record(sender.id.encode("hex"), "GET_FOLLOWERS")
        self.router.addContact(sender)
        if start is not None:
            ser = self.db.follow.get_followers(int(start))
        else:
            ser = self.db.follow.get_followers()
        return [ser[0], self.signing_key.sign(ser[0])[:64], ser[1]]

    def rpc_get_following(self, sender):
        self.log.info("serving following list to %s" % sender)
        self.audit.record(sender.id.encode("hex"), "GET_FOLLOWING")
        self.router.addContact(sender)
        ser = self.db.follow.get_following()
        if ser is None:
            return None
        else:
            return [ser, self.signing_key.sign(ser)[:64]]

    def rpc_broadcast(self, sender, message, signature):
        if len(message) <= 140 and self.db.follow.is_following(sender.id):
            try:
                verify_key = nacl.signing.VerifyKey(sender.pubkey)
                verify_key.verify(message, signature)
            except Exception:
                self.log.warning("received invalid broadcast from %s" % sender)
                return ["False"]
            self.log.info("received a broadcast from %s" % sender)
            self.router.addContact(sender)
            for listener in self.listeners:
                try:
                    verifyObject(BroadcastListener, listener)
                    listener.notify(sender.id, message)
                except DoesNotImplement:
                    pass
            return ["True"]
        else:
            return ["False"]

    def rpc_message(self, sender, pubkey, encrypted):
        try:
            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(pubkey))
            plaintext = box.decrypt(encrypted)
            p = PlaintextMessage()
            p.ParseFromString(plaintext)
            signature = p.signature
            p.ClearField("signature")
            verify_key = nacl.signing.VerifyKey(p.pubkey)
            verify_key.verify(p.SerializeToString(), signature)
            h = nacl.hash.sha512(p.pubkey)
            pow_hash = h[40:]
            if int(pow_hash[:6], 16) >= 50 or p.sender_guid.encode("hex") != h[:40] or p.sender_guid != sender.id:
                raise Exception('Invalid guid')
            self.log.info("received a message from %s" % sender)
            self.router.addContact(sender)
            for listener in self.listeners:
                try:
                    verifyObject(MessageListener, listener)
                    listener.notify(p, signature)
                except DoesNotImplement:
                    pass
            return ["True"]
        except Exception:
            self.log.warning("received invalid message from %s" % sender)
            return ["False"]

    def rpc_order(self, sender, pubkey, encrypted):
        try:
            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(pubkey))
            order = box.decrypt(encrypted)
            c = Contract(self.db, contract=json.loads(order, object_pairs_hook=OrderedDict),
                         testnet=self.multiplexer.testnet)
            v = c.verify(sender.pubkey)
            if v is True:
                self.router.addContact(sender)
                self.log.info("received an order from %s, waiting for payment..." % sender)
                payment_address = c.contract["buyer_order"]["order"]["payment"]["address"]
                chaincode = c.contract["buyer_order"]["order"]["payment"]["chaincode"]
                masterkey_b = c.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
                buyer_key = derive_childkey(masterkey_b, chaincode)
                amount = c.contract["buyer_order"]["order"]["payment"]["amount"]
                listing_hash = c.contract["vendor_offer"]["listing"]["contract_id"]
                signature = self.signing_key.sign(
                    str(payment_address) + str(amount) + str(listing_hash) + str(buyer_key))[:64]
                c.await_funding(self.get_notification_listener(), self.multiplexer.blockchain, signature, False)
                return [signature]
            else:
                self.log.warning("received invalid order from %s reason %s" % (sender, v))
                return ["False"]
        except Exception, e:
            self.log.error("Exception (%s) occurred processing order from %s" % (e.message, sender))
            return ["False"]

    def rpc_order_confirmation(self, sender, pubkey, encrypted):
        try:
            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(pubkey))
            order = box.decrypt(encrypted)
            c = Contract(self.db, contract=json.loads(order, object_pairs_hook=OrderedDict),
                         testnet=self.multiplexer.testnet)
            valid = c.accept_order_confirmation(self.get_notification_listener())
            if valid is True:
                self.router.addContact(sender)
                self.log.info("received confirmation for order %s" % c.get_order_id())
                return ["True"]
            else:
                self.log.warning("received invalid order confirmation from %s" % sender)
                return [valid]
        except Exception, e:
            self.log.error("unable to decrypt order confirmation from %s" % sender)
            return [str(e.message)]

    def rpc_complete_order(self, sender, pubkey, encrypted):
        try:
            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(pubkey))
            order = box.decrypt(encrypted)
            json.loads(order, object_pairs_hook=OrderedDict)
            temp = Contract(self.db, contract=json.loads(order, object_pairs_hook=OrderedDict),
                            testnet=self.multiplexer.testnet)
            c = Contract(self.db, hash_value=unhexlify(temp.get_order_id()),
                         testnet=self.multiplexer.testnet)

            contract_id = c.accept_receipt(self.get_notification_listener(),
                                           self.multiplexer.blockchain,
                                           receipt_json=json.dumps(temp.contract["buyer_receipt"], indent=4))
            self.router.addContact(sender)
            self.log.info("received receipt for order %s" % contract_id)
            return ["True"]
        except Exception, e:
            self.log.error("unable to parse receipt from %s" % sender)
            return [e.message]

    def rpc_dispute_open(self, sender, pubkey, encrypted):
        try:
            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(pubkey))
            order = box.decrypt(encrypted)
            contract = json.loads(order, object_pairs_hook=OrderedDict)
            process_dispute(contract, self.db, self.get_message_listener(),
                            self.get_notification_listener(), self.multiplexer.testnet)
            self.router.addContact(sender)
            self.log.info("Contract dispute opened by %s" % sender)
            return ["True"]
        except Exception as e:
            self.log.error("unable to parse disputed contract from %s" % sender)
            self.log.error("Exception: %s" % e.message)
            return ["False"]

    def rpc_dispute_close(self, sender, pubkey, encrypted):
        try:
            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(pubkey))
            res = box.decrypt(encrypted)
            resolution_json = json.loads(res, object_pairs_hook=OrderedDict)
            close_dispute(resolution_json, self.db, self.get_message_listener(),
                          self.get_notification_listener(), self.multiplexer.testnet)
            self.router.addContact(sender)
            self.log.info("Contract dispute closed by %s" % sender)
            return ["True"]
        except Exception:
            self.log.error("unable to parse disputed close message from %s" % sender)
            return ["False"]

    def rpc_get_ratings(self, sender, listing_hash=None):
        a = "ALL" if listing_hash is None else listing_hash.encode("hex")
        self.log.info("serving ratings for contract %s to %s" % (a, sender))
        self.audit.record(sender.id.encode("hex"), "GET_RATINGS", a)
        self.router.addContact(sender)
        try:
            ratings = []
            if listing_hash:
                for rating in self.db.ratings.get_listing_ratings(listing_hash.encode("hex")):
                    ratings.append(json.loads(rating[0], object_pairs_hook=OrderedDict))
            else:
                for rating in self.db.ratings.get_all_ratings():
                    ratings.append(json.loads(rating[0], object_pairs_hook=OrderedDict))
            ret = json.dumps(ratings).encode("zlib")
            return [str(ret), self.signing_key.sign(ret)[:64]]
        except Exception:
            self.log.warning("could not load ratings for contract %s" % a)
            return None

    def rpc_refund(self, sender, pubkey, encrypted):
        try:
            box = Box(self.signing_key.to_curve25519_private_key(), PublicKey(pubkey))
            refund = box.decrypt(encrypted)
            refund_json = json.loads(refund, object_pairs_hook=OrderedDict)
            c = Contract(self.db, hash_value=unhexlify(refund_json["refund"]["order_id"]),
                         testnet=self.multiplexer.testnet)
            c.process_refund(refund_json, self.multiplexer.blockchain, self.get_notification_listener())
            self.router.addContact(sender)
            self.log.info("order %s refunded by vendor" % refund_json["refund"]["order_id"])
            return ["True"]
        except Exception, e:
            self.log.error("unable to parse refund message from %s" % sender)
            return [e.message]

    def callGetContract(self, nodeToAsk, contract_hash):
        d = self.get_contract(nodeToAsk, contract_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetImage(self, nodeToAsk, image_hash):
        d = self.get_image(nodeToAsk, image_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetProfile(self, nodeToAsk):
        d = self.get_profile(nodeToAsk)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetUserMetadata(self, nodeToAsk):
        d = self.get_user_metadata(nodeToAsk)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetListings(self, nodeToAsk):
        d = self.get_listings(nodeToAsk)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetContractMetadata(self, nodeToAsk, contract_hash):
        d = self.get_contract_metadata(nodeToAsk, contract_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callFollow(self, nodeToAsk, proto, signature):
        d = self.follow(nodeToAsk, proto, signature)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callUnfollow(self, nodeToAsk, signature):
        d = self.unfollow(nodeToAsk, signature)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetFollowers(self, nodeToAsk, start=None):
        if start is None:
            d = self.get_followers(nodeToAsk)
        else:
            d = self.get_followers(nodeToAsk, start)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetFollowing(self, nodeToAsk):
        d = self.get_following(nodeToAsk)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callBroadcast(self, nodeToAsk, message, signature):
        d = self.broadcast(nodeToAsk, message, signature)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callMessage(self, nodeToAsk, ehemeral_pubkey, ciphertext):
        d = self.message(nodeToAsk, ehemeral_pubkey, ciphertext)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callOrder(self, nodeToAsk, ephem_pubkey, encrypted_contract):
        d = self.order(nodeToAsk, ephem_pubkey, encrypted_contract)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callOrderConfirmation(self, nodeToAsk, ephem_pubkey, encrypted_contract):
        d = self.order_confirmation(nodeToAsk, ephem_pubkey, encrypted_contract)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callCompleteOrder(self, nodeToAsk, ephem_pubkey, encrypted_contract):
        d = self.complete_order(nodeToAsk, ephem_pubkey, encrypted_contract)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callDisputeOpen(self, nodeToAsk, ephem_pubkey, encrypted_contract):
        d = self.dispute_open(nodeToAsk, ephem_pubkey, encrypted_contract)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callDisputeClose(self, nodeToAsk, ephem_pubkey, encrypted_contract):
        d = self.dispute_close(nodeToAsk, ephem_pubkey, encrypted_contract)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callGetRatings(self, nodeToAsk, listing_hash=None):
        if listing_hash is None:
            d = self.get_ratings(nodeToAsk)
        else:
            d = self.get_ratings(nodeToAsk, listing_hash)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def callRefund(self, nodeToAsk, order_id, refund):
        d = self.refund(nodeToAsk, order_id, refund)
        return d.addCallback(self.handleCallResponse, nodeToAsk)

    def handleCallResponse(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if result[0]:
            self.router.addContact(node)
        else:
            self.log.debug("no response from %s, removing from router" % node)
            self.router.removeContact(node)
        return result

    def get_notification_listener(self):
        for listener in self.listeners:
            try:
                verifyObject(NotificationListener, listener)
                return listener
            except DoesNotImplement:
                pass

    def get_message_listener(self):
        for listener in self.listeners:
            try:
                verifyObject(MessageListener, listener)
                return listener
            except DoesNotImplement:
                pass

    def __iter__(self):
        return iter(self.handled_commands)
