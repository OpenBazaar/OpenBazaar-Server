__author__ = 'chris'

import ast
import json
import os
import time
from constants import DATA_FOLDER
from market.profile import Profile
from keyutils.keys import KeyChain
from random import shuffle
from autobahn.twisted.websocket import WebSocketServerFactory, WebSocketServerProtocol
from protos.countries import CountryCode
from protos.objects import Plaintext_Message, Value, Listings
from protos import objects
from twisted.internet import defer
from binascii import unhexlify
from dht.node import Node


class WSProtocol(WebSocketServerProtocol):
    """
    Handles new incoming requests coming from a websocket.
    """

    def onOpen(self):
        self.factory.register(self)

    def get_vendors(self, message_id):
        if message_id in self.factory.outstanding:
            vendors = self.factory.outstanding[message_id]
        else:
            vendors = self.factory.db.VendorStore().get_vendors()
            shuffle(vendors)
            self.factory.outstanding[message_id] = vendors

        def count_results(results):
            to_query = 0
            for result in results:
                if not result:
                    to_query += 1
            for node in vendors[:to_query]:
                dl.append(self.factory.mserver.get_user_metadata(node).addCallback(handle_response, node))
                defer.gatherResults(dl).addCallback(count_results)

        def handle_response(metadata, node):
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
                self.sendMessage(json.dumps(vendor, indent=4), False)
                vendors.remove(node)
                return True
            else:
                self.factory.db.VendorStore().delete_vendor(node.id.encode("hex"))
                vendors.remove(node)
                return False

        dl = []
        for node in vendors[:30]:
            dl.append(self.factory.mserver.get_user_metadata(node).addCallback(handle_response, node))
        defer.gatherResults(dl).addCallback(count_results)

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
                        self.sendMessage(json.dumps(moderator, indent=4), False)
                    else:
                        m.delete_moderator(node.id)
                for mod in moderators:
                    try:
                        val = objects.Value()
                        val.ParseFromString(mod)
                        n = objects.Node()
                        n.ParseFromString(val.serializedData)
                        node_to_ask = Node(n.guid, n.ip, n.port, n.signedPublicKey)
                        if n.guid == KeyChain(self.factory.db).guid:
                            parse_profile(Profile(self.factory.db).get(), node_to_ask)
                        else:
                            self.factory.mserver.get_profile(node_to_ask)\
                                .addCallback(parse_profile, node_to_ask)
                    except Exception:
                        pass
        self.factory.kserver.get("moderators").addCallback(parse_response)

    def get_homepage_listings(self, message_id):
        if message_id not in self.factory.outstanding:
            self.factory.outstanding[message_id] = []
        vendors = self.factory.db.VendorStore().get_vendors()
        shuffle(vendors)

        def count_results(results):
            to_query = 30
            for result in results:
                to_query -= result
            shuffle(vendors)
            if to_query/3 > 0 and len(vendors) > 0:
                for node in vendors[:to_query/3]:
                    dl.append(self.factory.mserver.get_listings(node).addCallback(handle_response, node))
                defer.gatherResults(dl).addCallback(count_results)

        def handle_response(listings, node):
            count = 0
            if listings is not None:
                for l in listings.listing:
                    if l.contract_hash not in self.factory.outstanding[message_id]:
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
                        self.sendMessage(json.dumps(listing_json, indent=4), False)
                        count += 1
                        self.factory.outstanding[message_id].append(l.contract_hash)
                        if count == 3:
                            return count
                vendors.remove(node)
            else:
                self.factory.db.VendorStore().delete_vendor(node.id.encode("hex"))
                vendors.remove(node)
            return count

        dl = []
        for vendor in vendors[:10]:
            dl.append(self.factory.mserver.get_listings(vendor).addCallback(handle_response, vendor))
        defer.gatherResults(dl).addCallback(count_results)

    def send_message(self, guid, handle, message, subject, message_type, recipient_encryption_key):
        self.factory.db.MessageStore().save_message(guid, handle, "", unhexlify(recipient_encryption_key), subject,
                                                    message_type.upper(), message, time.time(), "", "", True)

        def send(node_to_send):
            n = node_to_send if node_to_send is not None else Node(unhexlify(guid), "123.4.5.6", 1234)
            self.factory.mserver.send_message(n, recipient_encryption_key,
                                              Plaintext_Message.Type.Value(message_type.upper()),
                                              message, subject)
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
                            "ships_to": []
                        }
                }
                for country in l.ships_to:
                    listing_json["listing"]["ships_to"].append(str(CountryCode.Name(country)))
                self.sendMessage(json.dumps(listing_json, indent=4), False)

        def parse_results(values):
            if values is not None:
                for v in values:
                    try:
                        val = Value()
                        val.ParseFromString(v)
                        n = objects.Node()
                        n.ParseFromString(val.serializedData)
                        node_to_ask = Node(n.guid, n.ip, n.port, n.signedPublicKey, True)
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

    def onMessage(self, payload, isBinary):
        try:
            request_json = json.loads(payload)
            if isinstance(request_json, unicode):
                payload = ast.literal_eval(payload)
                request_json = json.loads(payload)

            message_id = request_json["request"]["id"]

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

    def connectionLost(self, reason):
        WebSocketServerProtocol.connectionLost(self, reason)
        self.factory.unregister(self)


class WSFactory(WebSocketServerFactory):

    """
    Simple broadcast server broadcasting any message it receives to all
    currently connected clients.
    """

    def __init__(self, url, mserver, kserver, debug=False, debugCodePaths=False):
        WebSocketServerFactory.__init__(self, url, debug=debug, debugCodePaths=debugCodePaths)
        self.mserver = mserver
        self.kserver = kserver
        self.db = mserver.db
        self.outstanding = {}
        self.clients = []

    def register(self, client):
        if client not in self.clients:
            self.clients.append(client)

    def unregister(self, client):
        if client in self.clients:
            self.clients.remove(client)

    def push(self, msg):
        for c in self.clients:
            c.sendMessage(msg)
