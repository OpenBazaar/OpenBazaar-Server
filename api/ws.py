__author__ = 'chris'

import ast
import json
import os
import time
from constants import DATA_FOLDER
from market.profile import Profile
from keyutils.keys import KeyChain
from random import shuffle
from protos.countries import CountryCode
from protos.objects import PlaintextMessage, Value, Listings
from protos import objects
from binascii import unhexlify
from dht.node import Node
from twisted.internet.protocol import Protocol, Factory, connectionDone


# pylint: disable=W0232
class WSProtocol(Protocol):
    """
    Handles new incoming requests coming from a websocket.
    """

    def connectionMade(self):
        self.factory.register(self)

    def connectionLost(self, reason=connectionDone):
        self.factory.unregister(self)

    def get_vendors(self, message_id):
        if message_id in self.factory.outstanding_vendors:
            queried = self.factory.outstanding_vendors[message_id]
        else:
            queried = []
            self.factory.outstanding_vendors = {}
            self.factory.outstanding_vendors[message_id] = queried

        vendors = self.factory.db.VendorStore().get_vendors()

        shuffle(vendors)
        to_query = []
        for vendor in vendors:
            if vendor.id not in queried:
                to_query.append(vendor)

        def handle_response(metadata, node):
            to_query.remove(node)
            if metadata is not None:
                vendor = {
                    "id": message_id,
                    "vendor":
                        {
                            "guid": node.id.encode("hex"),
                            "name": metadata.name,
                            "short_description": metadata.short_description,
                            "handle": metadata.handle,
                            "avatar_hash": metadata.avatar_hash.encode("hex"),
                            "nsfw": metadata.nsfw
                        }
                }
                self.transport.write(json.dumps(vendor, indent=4))
                queried.append(node.id)
                return True
            else:
                self.factory.db.VendorStore().delete_vendor(node.id.encode("hex"))
                return False

        for node in to_query[:30]:
            self.factory.mserver.get_user_metadata(node).addCallback(handle_response, node)

    def get_moderators(self, message_id):
        m = self.factory.db.ModeratorStore()

        def parse_response(moderators):
            if moderators is not None:
                m.clear_all()

                def parse_profile(profile, node):
                    if profile is not None:
                        m.save_moderator(node.id.encode("hex"), node.signed_pubkey,
                                         profile.encryption_key.public_key,
                                         profile.encryption_key.signature, profile.bitcoin_key.public_key,
                                         profile.bitcoin_key.signature, profile.name, profile.avatar_hash,
                                         profile.moderation_fee, profile.handle, profile.short_description)
                        moderator = {
                            "id": message_id,
                            "moderator":
                                {
                                    "guid": node.id.encode("hex"),
                                    "name": profile.name,
                                    "handle": profile.handle,
                                    "short_description": profile.short_description,
                                    "avatar_hash": profile.avatar_hash.encode("hex"),
                                    "about": profile.about,
                                    "fee": profile.moderation_fee
                                }
                        }
                        self.transport.write(json.dumps(moderator, indent=4))
                    else:
                        m.delete_moderator(node.id)
                for mod in moderators:
                    try:
                        val = objects.Value()
                        val.ParseFromString(mod)
                        n = objects.Node()
                        n.ParseFromString(val.serializedData)
                        node_to_ask = Node(n.guid, n.nodeAddress.ip, n.nodeAddress.port, n.signedPublicKey,
                                           None if not n.HasField("relayAddress") else
                                           (n.relayAddress.ip, n.relayAddress.port),
                                           n.natType, n.vendor)
                        if n.guid == KeyChain(self.factory.db).guid:
                            parse_profile(Profile(self.factory.db).get(), node_to_ask)
                        else:
                            self.factory.mserver.get_profile(node_to_ask)\
                                .addCallback(parse_profile, node_to_ask)
                    except Exception:
                        pass
        self.factory.kserver.get("moderators").addCallback(parse_response)

    def get_homepage_listings(self, message_id):
        if message_id not in self.factory.outstanding_listings:
            self.factory.outstanding_listings = {}
            self.factory.outstanding_listings[message_id] = []

        vendors = self.factory.db.VendorStore().get_vendors()
        shuffle(vendors)

        def handle_response(listings, node):
            count = 0
            if listings is not None:
                for l in listings.listing:
                    try:
                        if l.contract_hash not in self.factory.outstanding_listings[message_id]:
                            listing_json = {
                                "id": message_id,
                                "listing":
                                    {
                                        "guid": node.id.encode("hex"),
                                        "handle": listings.handle,
                                        "avatar_hash": listings.avatar_hash.encode("hex"),
                                        "title": l.title,
                                        "contract_hash": l.contract_hash.encode("hex"),
                                        "thumbnail_hash": l.thumbnail_hash.encode("hex"),
                                        "category": l.category,
                                        "price": l.price,
                                        "currency_code": l.currency_code,
                                        "nsfw": l.nsfw,
                                        "origin": str(CountryCode.Name(l.origin)),
                                        "ships_to": []
                                    }
                            }
                            for country in l.ships_to:
                                listing_json["listing"]["ships_to"].append(str(CountryCode.Name(country)))
                            if not os.path.isfile(DATA_FOLDER + 'cache/' + l.thumbnail_hash.encode("hex")):
                                self.factory.mserver.get_image(node, l.thumbnail_hash)
                            if not os.path.isfile(DATA_FOLDER + 'cache/' + listings.avatar_hash.encode("hex")):
                                self.factory.mserver.get_image(node, listings.avatar_hash)
                            self.transport.write(json.dumps(listing_json, indent=4))
                            count += 1
                            self.factory.outstanding_listings[message_id].append(l.contract_hash)
                            if count == 3:
                                break
                    except Exception:
                        pass
                vendors.remove(node)
            else:
                self.factory.db.VendorStore().delete_vendor(node.id.encode("hex"))
                vendors.remove(node)

        for vendor in vendors[:15]:
            self.factory.mserver.get_listings(vendor).addCallback(handle_response, vendor)

    def send_message(self, guid, handle, message, subject, message_type, recipient_encryption_key):
        self.factory.db.MessageStore().save_message(guid, handle, "", unhexlify(recipient_encryption_key), subject,
                                                    message_type.upper(), message, time.time(), "", "", True)

        def send(node_to_send):
            n = node_to_send if node_to_send is not None else Node(unhexlify(guid))
            self.factory.mserver.send_message(n, recipient_encryption_key,
                                              PlaintextMessage.Type.Value(message_type.upper()),
                                              message, subject,
                                              store_only=True if node_to_send is None else False)
        self.factory.kserver.resolve(unhexlify(guid)).addCallback(send)

    def search(self, message_id, keyword):
        def respond(l, node):
            if l is not None:
                listing_json = {
                    "id": message_id,
                    "listing":
                        {
                            "guid": node.id.encode("hex"),
                            "title": l.title,
                            "contract_hash": l.contract_hash.encode("hex"),
                            "thumbnail_hash": l.thumbnail_hash.encode("hex"),
                            "category": l.category,
                            "price": l.price,
                            "currency_code": l.currency_code,
                            "nsfw": l.nsfw,
                            "origin": str(CountryCode.Name(l.origin)),
                            "ships_to": [],
                            "avatar_hash": l.avatar_hash.encode("hex"),
                            "handle": l.handle
                        }
                }
                for country in l.ships_to:
                    listing_json["listing"]["ships_to"].append(str(CountryCode.Name(country)))
                self.transport.write(json.dumps(listing_json, indent=4))

        def parse_results(values):
            if values is not None:
                for v in values:
                    try:
                        val = Value()
                        val.ParseFromString(v)
                        n = objects.Node()
                        n.ParseFromString(val.serializedData)
                        node_to_ask = Node(n.guid, n.nodeAddress.ip, n.nodeAddress.port, n.signedPublicKey,
                                           None if not n.HasField("relayAddress") else
                                           (n.relayAddress.ip, n.relayAddress.port),
                                           n.natType, n.vendor)
                        if n.guid == KeyChain(self.factory.db).guid:
                            proto = self.factory.db.ListingsStore().get_proto()
                            l = Listings()
                            l.ParseFromString(proto)
                            for listing in l.listing:
                                if listing.contract_hash == val.valueKey:
                                    respond(listing, node_to_ask)
                        else:
                            self.factory.mserver.get_contract_metadata(node_to_ask, val.valueKey)\
                                .addCallback(respond, node_to_ask)
                    except Exception:
                        pass
        self.factory.kserver.get(keyword.lower()).addCallback(parse_results)

    def dataReceived(self, payload):
        try:
            request_json = json.loads(payload)
            if isinstance(request_json, unicode):
                payload = ast.literal_eval(payload)
                request_json = json.loads(payload)

            message_id = str(request_json["request"]["id"])

            if request_json["request"]["command"] == "get_vendors":
                self.get_vendors(message_id)

            if request_json["request"]["command"] == "get_moderators":
                self.get_moderators(message_id)

            elif request_json["request"]["command"] == "get_homepage_listings":
                self.get_homepage_listings(message_id)

            elif request_json["request"]["command"] == "search":
                self.search(message_id, request_json["request"]["keyword"].lower())

            elif request_json["request"]["command"] == "send_message":
                self.send_message(request_json["request"]["guid"],
                                  request_json["request"]["handle"],
                                  request_json["request"]["message"],
                                  request_json["request"]["subject"],
                                  request_json["request"]["message_type"],
                                  request_json["request"]["recipient_key"])

        except Exception as e:
            print 'Exception occurred: %s' % e


class WSFactory(Factory):

    def __init__(self, mserver, kserver, only_ip="127.0.0.1"):
        self.mserver = mserver
        self.kserver = kserver
        self.db = mserver.db
        self.outstanding_listings = {}
        self.outstanding_vendors = {}
        self.protocol = WSProtocol
        self.only_ip = only_ip
        self.clients = []

    def buildProtocol(self, addr):
        if addr.host != self.only_ip and self.only_ip != "0.0.0.0":
            return
        return Factory.buildProtocol(self, addr)

    def register(self, client):
        if client not in self.clients:
            self.clients.append(client)

    def unregister(self, client):
        if client in self.clients:
            self.clients.remove(client)

    def push(self, msg):
        for c in self.clients:
            c.transport.write(msg)


