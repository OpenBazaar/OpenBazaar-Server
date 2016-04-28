__author__ = 'chris'

import ast
import json
import os
import time
from binascii import unhexlify
from random import shuffle

import nacl.encoding
import nacl.signing
from twisted.internet.protocol import Protocol, Factory, connectionDone
from txws import WebSocketProtocol, WebSocketFactory

from api.utils import smart_unicode, sanitize_html
from config import DATA_FOLDER, str_to_bool
from dht.node import Node
from keys.keychain import KeyChain
from log import Logger
from market.profile import Profile
from protos import objects
from protos.countries import CountryCode
from protos.objects import PlaintextMessage, Value, Listings

ALLOWED_TAGS = ('h2', 'h3', 'h4', 'h5', 'h6', 'p', 'a', 'u', 'ul', 'ol', 'nl', 'li', 'b', 'i', 'strong',
                'em', 'strike', 'hr', 'br', 'img', 'blockquote', 'span')


# pylint: disable=W0232
class WSProtocol(Protocol):
    """
    Handles new incoming requests coming from a websocket.
    """

    def __init__(self):
        self.log = Logger(system=self)

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

        vendors = self.factory.mserver.protocol.multiplexer.vendors.values()

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
                self.transport.write(json.dumps(sanitize_html(vendor), indent=4))
                queried.append(node.id)
                return True
            else:
                if node.id in self.factory.mserver.protocol.multiplexer.vendors:
                    del self.factory.mserver.protocol.multiplexer.vendors[node.id]
                self.factory.db.vendors.delete_vendor(node.id.encode("hex"))
                return False

        for node in to_query[:30]:
            self.factory.mserver.get_user_metadata(node).addCallback(handle_response, node)

    def get_moderators(self, message_id):

        def parse_response(moderators):
            if moderators is not None:
                current_mods = json.loads(self.factory.db.settings.get()[11])
                self.factory.db.moderators.clear_all(except_guids=current_mods)

                def parse_profile(profile, node):
                    if profile is not None:
                        # TODO: should check signatures here before entering in database
                        self.factory.db.moderators.save_moderator(node.id.encode("hex"), node.pubkey,
                                                                  profile.bitcoin_key.public_key,
                                                                  profile.bitcoin_key.signature, profile.name,
                                                                  profile.avatar_hash, profile.moderation_fee,
                                                                  profile.handle, profile.short_description)
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
                        self.transport.write(json.dumps(sanitize_html(moderator), indent=4))
                    else:
                        self.factory.db.moderators.delete_moderator(node.id)
                for mod in moderators:
                    try:
                        val = objects.Value()
                        val.ParseFromString(mod)
                        n = objects.Node()
                        n.ParseFromString(val.serializedData)
                        node_to_ask = Node(n.guid, n.nodeAddress.ip, n.nodeAddress.port, n.publicKey,
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

    def get_homepage_listings(self, message_id, only_following=False):
        if message_id not in self.factory.outstanding_listings:
            self.factory.outstanding_listings = {}
            self.factory.outstanding_listings[message_id] = []

        vendors = dict(self.factory.mserver.protocol.multiplexer.vendors)
        self.log.info("Fetching listings from %s vendors" % len(vendors))

        def get_following_from_vendors(vendors):
            follow_data = self.factory.mserver.db.follow.get_following()
            following_guids = []
            if follow_data is not None:
                f = objects.Following()
                f.ParseFromString(follow_data)
                for user in f.users:
                    following_guids.append(user.guid)
            vendor_list = []
            for k, v in vendors.items():
                if k in following_guids:
                    vendor_list.append(v)
            return vendor_list

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
                            if l.contract_type != 0:
                                listing_json["contract_type"] = str(Listings.ContractType.Name(l.contract_type))
                            for country in l.ships_to:
                                listing_json["listing"]["ships_to"].append(str(CountryCode.Name(country)))
                            if not os.path.isfile(os.path.join( \
                                    DATA_FOLDER, 'cache', l.thumbnail_hash.encode("hex"))):
                                self.factory.mserver.get_image(node, l.thumbnail_hash)
                            if not os.path.isfile(os.path.join( \
                                    DATA_FOLDER, 'cache', listings.avatar_hash.encode("hex"))):
                                self.factory.mserver.get_image(node, listings.avatar_hash)
                            self.transport.write(json.dumps(sanitize_html(listing_json), indent=4))
                            count += 1
                            self.factory.outstanding_listings[message_id].append(l.contract_hash)
                            if count == 3:
                                break
                    except Exception:
                        pass
                if node.id in vendors:
                    del vendors[node.id]
            else:
                if node.id in vendors:
                    del vendors[node.id]
                if node.id in self.factory.mserver.protocol.multiplexer.vendors:
                    del self.factory.mserver.protocol.multiplexer.vendors[node.id]
                    self.factory.db.vendors.delete_vendor(node.id.encode("hex"))
                if only_following:
                    vendor_list = get_following_from_vendors(vendors)
                else:
                    vendor_list = vendors.values()
                if len(vendor_list) > 0:
                    shuffle(vendor_list)
                    node_to_ask = vendor_list[0]
                    if node_to_ask is not None:
                        self.factory.mserver.get_listings(node_to_ask).addCallback(handle_response, node_to_ask)
        if only_following:
            vendor_list = get_following_from_vendors(vendors)
        else:
            vendor_list = vendors.values()
        shuffle(vendor_list)
        for vendor in vendor_list[:15]:
            self.factory.mserver.get_listings(vendor).addCallback(handle_response, vendor)

    def send_message(self, message_id, guid, handle, message, subject, message_type, recipient_key):

        enc_key = nacl.signing.VerifyKey(unhexlify(recipient_key)).to_curve25519_public_key().encode()

        self.factory.db.messages.save_message(guid, handle, unhexlify(recipient_key), subject,
                                              message_type.upper(), message, time.time(), "", "", True,
                                              message_id)

        def send(node_to_send):
            n = node_to_send if node_to_send is not None else Node(unhexlify(guid))
            self.factory.mserver.send_message(n, enc_key,
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
                    self.transport.write(json.dumps(sanitize_html(listing_json), indent=4))

        def parse_results(values):
            if values is not None:
                for v in values:
                    try:
                        val = Value()
                        val.ParseFromString(v)
                        n = objects.Node()
                        n.ParseFromString(val.serializedData)
                        node_to_ask = Node(n.guid, n.nodeAddress.ip, n.nodeAddress.port, n.publicKey,
                                           None if not n.HasField("relayAddress") else
                                           (n.relayAddress.ip, n.relayAddress.port),
                                           n.natType, n.vendor)
                        if n.guid == KeyChain(self.factory.db).guid:
                            proto = self.factory.db.listings.get_proto()
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
                self.get_homepage_listings(message_id,
                                           str_to_bool(request_json["request"]["only_following"])
                                           if "only_following" in request_json["request"] else False)

            elif request_json["request"]["command"] == "search":
                self.search(message_id, request_json["request"]["keyword"].lower())

            elif request_json["request"]["command"] == "send_message":
                self.send_message(message_id, request_json["request"]["guid"],
                                  request_json["request"]["handle"],
                                  smart_unicode(request_json["request"]["message"]),
                                  request_json["request"]["subject"],
                                  request_json["request"]["message_type"],
                                  request_json["request"]["public_key"])

        except Exception as e:
            print 'Exception occurred: %s' % e


class WSFactory(Factory):

    def __init__(self, mserver, kserver, only_ip=None):
        if only_ip == None:
            only_ip = ["127.0.0.1"]
        self.mserver = mserver
        self.kserver = kserver
        self.db = mserver.db
        self.outstanding_listings = {}
        self.outstanding_vendors = {}
        self.protocol = WSProtocol
        self.only_ip = only_ip
        self.clients = []

    def buildProtocol(self, addr):
        if addr.host not in self.only_ip and "0.0.0.0" not in self.only_ip:
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


class AuthenticatedWebSocketProtocol(WebSocketProtocol):

    def validateHeaders(self):
        if "Cookie" in self.headers:
            for session in self.factory.authenticated_sessions:
                if "TWISTED_SESSION=" + session.uid in self.headers["Cookie"]:
                    return WebSocketProtocol.validateHeaders(self)
        return False


class AuthenticatedWebSocketFactory(WebSocketFactory):

    authenticated_sessions = None
