__author__ = 'chris'

import json
import os
import obelisk
import nacl.encoding
from binascii import unhexlify
from collections import OrderedDict
from functools import wraps
from txrestapi.resource import APIResource
from txrestapi.methods import GET, POST, DELETE
from twisted.web import server
from twisted.web.resource import NoResource
from twisted.web import http
from twisted.web.server import Site
from twisted.internet import defer, reactor, task
from twisted.protocols.basic import FileSender

from config import DATA_FOLDER, RESOLVER, delete_value, set_value, get_value, str_to_bool, TRANSACTION_FEE
from protos.countries import CountryCode
from protos import objects
from keys import blockchainid
from keys.keychain import KeyChain
from dht.utils import digest
from market.profile import Profile
from market.contracts import Contract, check_order_for_payment
from market.btcprice import BtcPrice
from net.upnp import PortMapper
from api.utils import sanitize_html

DEFAULT_RECORDS_COUNT = 20
DEFAULT_RECORDS_OFFSET = 0


class OpenBazaarAPI(APIResource):
    """
    This RESTful API allows clients to pull relevant data from the
    OpenBazaar daemon for use in a GUI or other application.
    """

    # pylint: disable=E0213, E1102
    def authenticated(func):
        def _authenticate(self, request):
            session = request.getSession()
            if session not in self.authenticated_sessions:
                session.expire()
                request.setResponseCode(401)
                request.write('<html><body><div><span style="color:red">Authorization Error</span></div>'
                              '<h2>Permission Denied</h2></body></html>')
                request.finish()
                return server.NOT_DONE_YET
            else:
                if request.getHeader("Content-Type") == "application/json":
                    request.args = json.loads(request.content.read())
                func(self, request)
                return server.NOT_DONE_YET
        return wraps(func)(_authenticate)

    def __init__(self, mserver, kserver, protocol, username, password, authenticated_sessions):
        self.mserver = mserver
        self.kserver = kserver
        self.protocol = protocol
        self.db = mserver.db
        self.keychain = KeyChain(self.db)
        self.username = username
        self.password = password
        self.authenticated_sessions = authenticated_sessions
        self.failed_login_attempts = {}
        task.LoopingCall(self._keep_sessions_alive).start(890, False)
        APIResource.__init__(self)

    def _keep_sessions_alive(self):
        for session in self.authenticated_sessions:
            session.touch()

    def _failed_login(self, host):
        def remove_ban(host):
            del self.failed_login_attempts[host]
        if host in self.failed_login_attempts:
            self.failed_login_attempts[host] += 1
            reactor.callLater(3600, remove_ban, host)
        else:
            self.failed_login_attempts[host] = 1

    @POST('^/api/v1/login')
    def login(self, request):
        request.setHeader('content-type', "application/json")
        if request.getHost().host in self.failed_login_attempts and \
                        self.failed_login_attempts[request.getHost().host] >= 7:
            return json.dumps({"success": False, "reason": "too many attempts"})
        try:
            if request.args["username"][0] == self.username and request.args["password"][0] == self.password:
                self.authenticated_sessions.append(request.getSession())
                if request.getHost().host in self.failed_login_attempts:
                    del self.failed_login_attempts[request.getHost().host]
                return json.dumps({"success": True})
            else:
                raise Exception("Invalid credentials")
        except Exception:
            self._failed_login(request.getHost().host)
            return json.dumps({"success": False, "reason": "invalid username or password"})


    @GET('^/api/v1/get_image')
    @authenticated
    def get_image(self, request):
        @defer.inlineCallbacks
        def _showImage(resp=None):
            @defer.inlineCallbacks
            def _setContentDispositionAndSend(file_path, extension, content_type):
                request.setHeader('content-disposition', 'filename="%s.%s"' % (file_path, extension))
                request.setHeader('content-type', content_type)
                request.setHeader('cache-control', 'max-age=604800')

                f = open(file_path, "rb")
                yield FileSender().beginFileTransfer(f, request)
                f.close()
                defer.returnValue(0)

            if os.path.exists(image_path):
                yield _setContentDispositionAndSend(image_path, "jpg", "image/jpeg")
            else:
                request.setResponseCode(http.NOT_FOUND)
                request.write("No such image '%s'" % request.path)
            request.finish()

        if "hash" in request.args and len(request.args["hash"][0]) == 40:
            if self.db.filemap.get_file(request.args["hash"][0]) is not None:
                image_path = self.db.filemap.get_file(request.args["hash"][0])
            else:
                image_path = os.path.join(DATA_FOLDER, "cache", request.args["hash"][0])
            if not os.path.exists(image_path) and "guid" in request.args:
                node = None
                for connection in self.protocol.values():
                    if connection.handler.node is not None and \
                                    connection.handler.node.id == unhexlify(request.args["guid"][0]):
                        node = connection.handler.node
                        self.mserver.get_image(node, unhexlify(request.args["hash"][0])).addCallback(_showImage)
                if node is None:
                    _showImage()
            else:
                _showImage()
        else:
            request.write(NoResource().render(request))
            request.finish()

        return server.NOT_DONE_YET

    @GET('^/api/v1/profile')
    @authenticated
    def get_profile(self, request):
        def parse_profile(profile, temp_handle=None):
            if profile is not None:
                profile_json = {
                    "profile": {
                        "name": profile.name,
                        "location": str(CountryCode.Name(profile.location)),
                        "public_key": profile.guid_key.public_key.encode("hex"),
                        "nsfw": profile.nsfw,
                        "vendor": profile.vendor,
                        "moderator": profile.moderator,
                        "moderation_fee": round(profile.moderation_fee, 2),
                        "handle": profile.handle,
                        "about": profile.about,
                        "short_description": profile.short_description,
                        "website": profile.website,
                        "email": profile.email,
                        "primary_color": profile.primary_color,
                        "secondary_color": profile.secondary_color,
                        "background_color": profile.background_color,
                        "text_color": profile.text_color,
                        "pgp_key": profile.pgp_key.public_key,
                        "avatar_hash": profile.avatar_hash.encode("hex"),
                        "header_hash": profile.header_hash.encode("hex"),
                        "social_accounts": {}
                    }
                }
                if temp_handle:
                    profile_json["profile"]["temp_handle"] = temp_handle
                if "guid" in request.args:
                    profile_json["profile"]["guid"] = request.args["guid"][0]
                else:
                    profile_json["profile"]["guid"] = self.keychain.guid.encode("hex")
                for account in profile.social:
                    profile_json["profile"]["social_accounts"][str(
                        objects.Profile.SocialAccount.SocialType.Name(account.type)).lower()] = {
                            "username": account.username,
                            "proof_url": account.proof_url
                        }
                if (profile.handle is not "" and "(unconfirmed)" not in profile.handle and
                        not blockchainid.validate(profile.handle, profile_json["profile"]["guid"])):
                    profile_json["profile"]["handle"] = ""
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(sanitize_html(profile_json), indent=4))
                request.finish()
            else:
                request.write(json.dumps({}))
                request.finish()
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    self.mserver.get_profile(node).addCallback(parse_profile)
                else:
                    request.write(json.dumps({}))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            p = Profile(self.db).get()
            if not p.HasField("guid_key"):
                request.write(json.dumps({}))
                request.finish()
            else:
                temp_handle = self.db.profile.get_temp_handle()
                parse_profile(p, None if temp_handle == "" else temp_handle)
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_listings')
    @authenticated
    def get_listings(self, request):
        def parse_listings(listings):
            if listings is not None:
                response = {"listings": []}
                for l in listings.listing:
                    listing_json = {
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
                    for country in l.ships_to:
                        listing_json["ships_to"].append(str(CountryCode.Name(country)))
                    response["listings"].append(listing_json)
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(sanitize_html(response), indent=4))
                request.finish()
            else:
                request.write(json.dumps({}))
                request.finish()

        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    self.mserver.get_listings(node).addCallback(parse_listings)
                else:
                    request.write(json.dumps({}))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            ser = self.db.listings.get_proto()
            if ser is not None:
                l = objects.Listings()
                l.ParseFromString(ser)
                parse_listings(l)
            else:
                parse_listings(None)
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_followers')
    @authenticated
    def get_followers(self, request):
        def parse_followers(followers):
            if followers is not None:
                response = {"followers": []}
                for f in followers.followers:
                    follower_json = {
                        "guid": f.guid.encode("hex"),
                        "handle": f.metadata.handle,
                        "name": f.metadata.name,
                        "avatar_hash": f.metadata.avatar_hash.encode("hex"),
                        "short_description": f.metadata.short_description,
                        "nsfw": f.metadata.nsfw
                    }
                    response["followers"].append(follower_json)
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(sanitize_html(response), indent=4))
                request.finish()
            else:
                request.write(json.dumps({}))
                request.finish()
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    self.mserver.get_followers(node).addCallback(parse_followers)
                else:
                    request.write(json.dumps({}))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            ser = self.db.follow.get_followers()
            if ser is not None:
                f = objects.Followers()
                f.ParseFromString(ser)
                parse_followers(f)
            else:
                parse_followers(None)
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_following')
    @authenticated
    def get_following(self, request):
        def parse_following(following):
            if following is not None:
                response = {"following": []}
                for f in following.users:
                    user_json = {
                        "guid": f.guid.encode("hex"),
                        "handle": f.metadata.handle,
                        "name": f.metadata.name,
                        "avatar_hash": f.metadata.avatar_hash.encode("hex"),
                        "short_description": f.metadata.short_description,
                        "nsfw": f.metadata.nsfw
                    }
                    response["following"].append(user_json)
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(sanitize_html(response), indent=4))
                request.finish()
            else:
                request.write(json.dumps({}))
                request.finish()

        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    self.mserver.get_following(node).addCallback(parse_following)
                else:
                    request.write(json.dumps({}))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            ser = self.db.follow.get_following()
            if ser is not None:
                f = objects.Following()
                f.ParseFromString(ser)
                parse_following(f)
            else:
                parse_following(None)
        return server.NOT_DONE_YET

    @POST('^/api/v1/follow')
    @authenticated
    def follow(self, request):
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    self.mserver.follow(node)
                    request.write(json.dumps({"success": True}))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": "could not resolve guid"}, indent=4))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
            return server.NOT_DONE_YET

    @POST('^/api/v1/unfollow')
    @authenticated
    def unfollow(self, request):
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    self.mserver.unfollow(node)
                    request.write(json.dumps({"success": True}))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": "could not resolve guid"}, indent=4))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
            return server.NOT_DONE_YET

    # pylint: disable=R0201
    @POST('^/api/v1/profile')
    @authenticated
    def update_profile(self, request):
        try:
            p = Profile(self.db)
            can_update_profile = (p.get().HasField("guid_key") or
                                  ("name" in request.args and
                                   "location" in request.args))
            if not can_update_profile:
                request_dict = {
                    "success": False,
                    "reason": "name or location not included"
                }
                request.write(json.dumps(request_dict, indent=4))
                request.finish()
                return False

            u = objects.Profile()
            if "name" in request.args:
                u.name = request.args["name"][0].decode("utf8")
            if "location" in request.args:
                # This needs to be formatted. Either here or from the UI.
                u.location = CountryCode.Value(request.args["location"][0].upper())
            if "handle" in request.args:
                if blockchainid.validate(request.args["handle"][0], self.keychain.guid.encode("hex")):
                    u.handle = request.args["handle"][0].decode("utf8")
                    self.db.profile.set_temp_handle("")
                else:
                    u.handle = ""
                    self.db.profile.set_temp_handle(request.args["handle"][0].decode("utf8"))
            if "about" in request.args:
                u.about = request.args["about"][0].decode("utf8")
            if "short_description" in request.args:
                u.short_description = request.args["short_description"][0].decode("utf8")
            if "nsfw" in request.args:
                p.profile.nsfw = str_to_bool(request.args["nsfw"][0])
            if "vendor" in request.args:
                p.profile.vendor = str_to_bool(request.args["vendor"][0])
            if "moderator" in request.args:
                p.profile.moderator = str_to_bool(request.args["moderator"][0])
            if "moderation_fee" in request.args:
                p.profile.moderation_fee = round(float(request.args["moderation_fee"][0]), 2)
            if "website" in request.args:
                u.website = request.args["website"][0].decode("utf8")
            if "email" in request.args:
                u.email = request.args["email"][0].decode("utf8")
            if "primary_color" in request.args:
                p.profile.primary_color = int(request.args["primary_color"][0])
            if "secondary_color" in request.args:
                p.profile.secondary_color = int(request.args["secondary_color"][0])
            if "background_color" in request.args:
                p.profile.background_color = int(request.args["background_color"][0])
            if "text_color" in request.args:
                p.profile.text_color = int(request.args["text_color"][0])
            if "avatar" in request.args:
                u.avatar_hash = unhexlify(request.args["avatar"][0])
            if "header" in request.args:
                u.header_hash = unhexlify(request.args["header"][0])
            if "pgp_key" in request.args and "signature" in request.args:
                p.add_pgp_key(request.args["pgp_key"][0], request.args["signature"][0],
                              self.keychain.guid.encode("hex"))
            if not p.get().HasField("guid_key"):
                key = u.PublicKey()
                key.public_key = self.keychain.verify_key.encode()
                key.signature = self.keychain.signing_key.sign(key.public_key)[:64]
                u.guid_key.MergeFrom(key)
            p.update(u)
            request.write(json.dumps({"success": True}))
            request.finish()
            self.kserver.node.vendor = p.get().vendor
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/social_accounts')
    @authenticated
    def add_social_account(self, request):
        try:
            p = Profile(self.db)
            if "account_type" in request.args and "username" in request.args:
                p.add_social_account(request.args["account_type"][0].decode("utf8"),
                                     request.args["username"][0].decode("utf8"),
                                     request.args["proof"][0].decode("utf8") if
                                     "proof" in request.args else None)
            else:
                raise Exception("Missing required fields")
            request.write(json.dumps({"success": True}))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @DELETE('^/api/v1/social_accounts')
    @authenticated
    def delete_social_account(self, request):
        try:
            p = Profile(self.db)
            if "account_type" in request.args:
                p.remove_social_account(request.args["account_type"][0])
            request.write(json.dumps({"success": True}))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/contracts')
    @authenticated
    def get_contract(self, request):
        def parse_contract(contract):
            if contract is not None:
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(sanitize_html(contract), indent=4))
                request.finish()
            else:
                request.write(json.dumps({}))
                request.finish()

        if "id" in request.args and len(request.args["id"][0]) == 40:
            if "guid" in request.args and len(request.args["guid"][0]) == 40:
                def get_node(node):
                    if node is not None:
                        self.mserver.get_contract(node, unhexlify(request.args["id"][0]))\
                            .addCallback(parse_contract)
                    else:
                        request.write(json.dumps({}))
                        request.finish()
                self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
            else:
                try:
                    with open(self.db.filemap.get_file(request.args["id"][0]), "r") as filename:
                        contract = json.loads(filename.read(), object_pairs_hook=OrderedDict)
                    parse_contract(contract)
                except Exception:
                    parse_contract(None)
        else:
            request.write(json.dumps({}))
            request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/contracts')
    @authenticated
    def set_contract(self, request):
        try:
            if "options" in request.args:
                options = {}
                for option in request.args["options"]:
                    options[option.decode("utf8")] = request.args[option.decode("utf8")]
            keywords = None
            if "keywords" in request.args:
                keywords = []
                for keyword in request.args["keywords"]:
                    keywords.append(keyword.decode("utf8"))
                if len(keywords) > 10:
                    raise Exception("Too many keywords")
            if "contract_id" in request.args:
                c = Contract(self.db, hash_value=unhexlify(request.args["contract_id"][0]),
                             testnet=self.protocol.testnet)
            else:
                c = Contract(self.db, testnet=self.protocol.testnet)
            c.create(
                str(request.args["expiration_date"][0]),
                request.args["metadata_category"][0],
                request.args["title"][0].decode("utf8"),
                request.args["description"][0].decode("utf8"),
                request.args["currency_code"][0],
                request.args["price"][0],
                request.args["process_time"][0].decode("utf8"),
                str_to_bool(request.args["nsfw"][0]),
                shipping_origin=request.args["shipping_origin"][0] if "shipping_origin" in request.args else None,
                shipping_regions=request.args["ships_to"] if "ships_to" in request.args else None,
                est_delivery_domestic=request.args["est_delivery_domestic"][0].decode("utf8")
                if "est_delivery_domestic" in request.args else None,
                est_delivery_international=request.args["est_delivery_international"][0].decode("utf8")
                if "est_delivery_international" in request.args else None,
                terms_conditions=request.args["terms_conditions"][0].decode("utf8")
                if request.args["terms_conditions"][0] is not "" else None,
                returns=request.args["returns"][0].decode("utf8")
                if request.args["returns"][0] is not "" else None,
                shipping_currency_code=request.args["shipping_currency_code"][0],
                shipping_domestic=request.args["shipping_domestic"][0],
                shipping_international=request.args["shipping_international"][0],
                keywords=keywords,
                category=request.args["category"][0].decode("utf8")
                if request.args["category"][0] is not "" else None,
                condition=request.args["condition"][0].decode("utf8")
                if request.args["condition"][0] is not "" else None,
                sku=request.args["sku"][0].decode("utf8") if request.args["sku"][0] is not "" else None,
                images=request.args["images"],
                free_shipping=str_to_bool(request.args["free_shipping"][0]),
                options=options if "options" in request.args else None,
                moderators=request.args["moderators"] if "moderators" in request.args else None,
                contract_id=request.args["contract_id"][0] if "contract_id" in request.args else None)

            for keyword in request.args["keywords"]:
                if keyword != "":
                    self.kserver.set(digest(keyword.lower()), unhexlify(c.get_contract_id()),
                                     self.kserver.node.getProto().SerializeToString())
            request.write(json.dumps({"success": True, "id": c.get_contract_id()}))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @DELETE('^/api/v1/contracts')
    @authenticated
    def delete_contract(self, request):
        try:
            if "id" in request.args:
                file_path = self.db.filemap.get_file(request.args["id"][0])
                with open(file_path, 'r') as filename:
                    contract = json.load(filename, object_pairs_hook=OrderedDict)
                c = Contract(self.db, contract=contract)
                if "keywords" in c.contract["vendor_offer"]["listing"]["item"]:
                    for keyword in c.contract["vendor_offer"]["listing"]["item"]["keywords"]:
                        if keyword != "":
                            if isinstance(keyword, unicode):
                                keyword = keyword.encode('utf8')
                            self.kserver.delete(keyword.lower(), unhexlify(c.get_contract_id()),
                                                self.keychain.signing_key.sign(
                                                    unhexlify(c.get_contract_id()))[:64])
                if "delete_images" in request.args:
                    c.delete(delete_images=True)
                else:
                    c.delete()
            request.write(json.dumps({"success": True}))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/shutdown')
    def shutdown(self, request):
        session = request.getSession()
        if session not in self.authenticated_sessions and request.getHost().host != "127.0.0.1":
            session.expire()
            request.setResponseCode(401)
            request.write('<html><body><div><span style="color:red">Authorization Error</span></div>'
                          '<h2>Permission Denied</h2></body></html>')
            request.finish()
            return server.NOT_DONE_YET
        else:
            for vendor in self.protocol.vendors.values():
                self.db.vendors.save_vendor(vendor.id.encode("hex"), vendor.getProto().SerializeToString())
            PortMapper().clean_my_mappings(self.kserver.node.port)
            self.protocol.shutdown()
            reactor.stop()
            return

    @POST('^/api/v1/make_moderator')
    @authenticated
    def make_moderator(self, request):
        try:
            self.mserver.make_moderator()
            request.write(json.dumps({"success": True}))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/unmake_moderator')
    @authenticated
    def unmake_moderator(self, request):
        try:
            self.mserver.unmake_moderator()
            request.write(json.dumps({"success": True}))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/purchase_contract')
    @authenticated
    def purchase_contract(self, request):
        try:
            def handle_response(resp, contract):
                if resp:
                    contract.await_funding(self.mserver.protocol.get_notification_listener(),
                                           self.protocol.blockchain, resp)
                    request.write(json.dumps({"success": True, "payment_address": payment[0],
                                              "amount": payment[1],
                                              "order_id": c.get_order_id()},
                                             indent=4))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": "vendor rejected contract"}, indent=4))
                    request.finish()
            options = None
            if "options" in request.args:
                options = {}
                for option in request.args["options"]:
                    options[option] = request.args[option][0]
            c = Contract(self.db, hash_value=unhexlify(request.args["id"][0]), testnet=self.protocol.testnet)
            payment = c.\
                add_purchase_info(int(request.args["quantity"][0]),
                                  request.args["refund_address"][0],
                                  request.args["ship_to"][0].decode("utf8")
                                  if "ship_to" in request.args else None,
                                  request.args["address"][0].decode("utf8")
                                  if "address" in request.args else None,
                                  request.args["city"][0].decode("utf8")
                                  if "city" in request.args else None,
                                  request.args["state"][0].decode("utf8")
                                  if "state" in request.args else None,
                                  request.args["postal_code"][0].decode("utf8")
                                  if "postal_code" in request.args else None,
                                  request.args["country"][0].decode("utf8")
                                  if "country" in request.args else None,
                                  request.args["moderator"][0] if "moderator" in request.args else None,
                                  options)

            def get_node(node):
                if node is not None:
                    self.mserver.purchase(node, c).addCallback(handle_response, c)
                else:
                    request.write(json.dumps({"success": False, "reason": "unable to reach vendor"}, indent=4))
                    request.finish()
            vendor_guid = unhexlify(c.contract["vendor_offer"]["listing"]["id"]["guid"])
            self.kserver.resolve(vendor_guid).addCallback(get_node)
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/confirm_order')
    @authenticated
    def confirm_order(self, request):
        try:
            def respond(success):
                if success is True:
                    request.write(json.dumps({"success": True}))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": success}))
                    request.finish()
            file_name = request.args["id"][0] + ".json"
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", file_name)
            with open(file_path, 'r') as filename:
                order = json.load(filename, object_pairs_hook=OrderedDict)
            c = Contract(self.db, contract=order, testnet=self.protocol.testnet)
            if "vendor_order_confirmation" not in c.contract:
                c.add_order_confirmation(self.protocol.blockchain,
                                         request.args["payout_address"][0],
                                         comments=request.args["comments"][0].decode("utf8")
                                         if "comments" in request.args else None,
                                         shipper=request.args["shipper"][0].decode("utf8")
                                         if "shipper" in request.args else None,
                                         tracking_number=request.args["tracking_number"][0].decode("utf8")
                                         if "tracking_number" in request.args else None,
                                         est_delivery=request.args["est_delivery"][0].decode("utf8")
                                         if "est_delivery" in request.args else None,
                                         url=request.args["url"][0].decode("utf8")
                                         if "url" in request.args else None,
                                         password=request.args["password"][0].decode("utf8")
                                         if "password" in request.args else None)
            guid = c.contract["buyer_order"]["order"]["id"]["guid"]
            self.mserver.confirm_order(guid, c).addCallback(respond)
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/upload_image')
    @authenticated
    def upload_image(self, request):
        try:
            ret = []
            if "image" in request.args:
                for image in request.args["image"]:
                    img = image.decode('base64')
                    hash_value = digest(img).encode("hex")
                    with open(os.path.join(DATA_FOLDER, "store", "media", hash_value), 'wb') as outfile:
                        outfile.write(img)
                    self.db.filemap.insert(hash_value, os.path.join("store", "media", hash_value))
                    ret.append(hash_value)
            elif "avatar" in request.args:
                avi = request.args["avatar"][0].decode("base64")
                hash_value = digest(avi).encode("hex")
                with open(os.path.join(DATA_FOLDER, "store", "avatar"), 'wb') as outfile:
                    outfile.write(avi)
                self.db.filemap.insert(hash_value, os.path.join("store", "avatar"))
                ret.append(hash_value)
            elif "header" in request.args:
                hdr = request.args["header"][0].decode("base64")
                hash_value = digest(hdr).encode("hex")
                with open(os.path.join(DATA_FOLDER, "store", "header"), 'wb') as outfile:
                    outfile.write(hdr)
                self.db.filemap.insert(hash_value, os.path.join("store", "header"))
                ret.append(hash_value)
            request.write(json.dumps({"success": True, "image_hashes": ret}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/complete_order')
    @authenticated
    def complete_order(self, request):
        def respond(success):
            if success is True:
                request.write(json.dumps({"success": True}))
                request.finish()
            else:
                request.write(json.dumps({"success": False, "reason": success}))
                request.finish()
        file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", request.args["id"][0] + ".json")
        if not os.path.exists(file_path):
            file_path = os.path.join(DATA_FOLDER, "purchases", "trade receipts", request.args["id"][0] + ".json")
        with open(file_path, 'r') as filename:
            order = json.load(filename, object_pairs_hook=OrderedDict)
        c = Contract(self.db, contract=order, testnet=self.protocol.testnet)
        if "buyer_receipt" not in c.contract:
            c.add_receipt(True,
                          self.protocol.blockchain,
                          feedback=request.args["feedback"][0] if "feedback" in request.args else None,
                          quality=request.args["quality"][0] if "quality" in request.args else None,
                          description=request.args["description"][0] if "description" in request.args else None,
                          delivery_time=request.args["delivery_time"][0]
                          if "delivery_time" in request.args else None,
                          customer_service=request.args["customer_service"][0]
                          if "customer_service" in request.args else None,
                          review=request.args["review"][0].decode("utf8") if "review" in request.args else "",
                          anonymous=str_to_bool(request.args["anonymous"]) if "anonymous" in request.args else True)
        guid = c.contract["vendor_offer"]["listing"]["id"]["guid"]
        self.mserver.complete_order(guid, c).addCallback(respond)
        return server.NOT_DONE_YET

    @POST('^/api/v1/settings')
    @authenticated
    def set_settings(self, request):
        try:
            settings = self.db.settings
            resolver = RESOLVER if "resolver" not in request.args or request.args["resolver"][0] == "" \
                else request.args["resolver"][0]
            if "libbitcoin_server" in request.args and \
                            request.args["libbitcoin_server"][0] != "" and \
                            request.args["libbitcoin_server"][0] != "null":
                if self.protocol.testnet:
                    set_value("LIBBITCOIN_SERVERS_TESTNET", "testnet_server_custom",
                              request.args["libbitcoin_server"][0])
                else:
                    set_value("LIBBITCOIN_SERVERS", "mainnet_server_custom",
                              request.args["libbitcoin_server"][0])
            else:
                if self.protocol.testnet:
                    if get_value("LIBBITCOIN_SERVERS_TESTNET", "testnet_server_custom"):
                        delete_value("LIBBITCOIN_SERVERS_TESTNET", "testnet_server_custom")
                else:
                    if get_value("LIBBITCOIN_SERVERS", "mainnet_server_custom"):
                        delete_value("LIBBITCOIN_SERVERS", "mainnet_server_custom")
            if resolver != get_value("CONSTANTS", "RESOLVER"):
                set_value("CONSTANTS", "RESOLVER", resolver)

            settings_list = settings.get()
            if "moderators" in request.args and settings_list is not None:
                mod_json = settings_list[11]
                if mod_json != "":
                    prev_mods = json.loads(mod_json)
                    current_mods = request.args["moderators"]
                    to_add = list(set(current_mods) - set(prev_mods))
                    to_remove = list(set(prev_mods) - set(current_mods))
                    if len(to_remove) > 0 or len(to_add) > 0:
                        self.mserver.update_moderators_on_listings(request.args["moderators"])

            settings.update(
                request.args["refund_address"][0],
                request.args["currency_code"][0],
                request.args["country"][0],
                request.args["language"][0],
                request.args["time_zone"][0],
                1 if str_to_bool(request.args["notifications"][0]) else 0,
                json.dumps(request.args["shipping_addresses"] if request.args["shipping_addresses"] != "" else []),
                json.dumps(request.args["blocked"] if request.args["blocked"] != "" else []),
                request.args["terms_conditions"][0],
                request.args["refund_policy"][0],
                json.dumps(request.args["moderators"] if request.args["moderators"] != "" else [])
            )

            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/settings')
    @authenticated
    def get_settings(self, request):
        settings = self.db.settings.get()
        if settings is None:
            request.write(json.dumps({}, indent=4))
            request.finish()
        else:
            if self.protocol.nat_type == objects.FULL_CONE:
                nat_type = "Open"
            elif self.protocol.nat_type == objects.RESTRICTED:
                nat_type = "Restricted"
            else:
                nat_type = "Severely Restricted"
            settings_json = {
                "refund_address": settings[1],
                "currency_code": settings[2],
                "country": settings[3],
                "language": settings[4],
                "time_zone": settings[5],
                "notifications": True if settings[6] == 1 else False,
                "shipping_addresses": json.loads(settings[7]),
                "blocked_guids": json.loads(settings[8]),
                "libbitcoin_server": get_value(
                    "LIBBITCOIN_SERVERS_TESTNET", "testnet_server_custom")if self.protocol.testnet else get_value(
                        "LIBBITCOIN_SERVERS", "server_custom"),
                "seed": KeyChain(self.db).signing_key.encode(encoder=nacl.encoding.HexEncoder),
                "terms_conditions": "" if settings[9] is None else settings[9],
                "refund_policy": "" if settings[10] is None else settings[10],
                "resolver": get_value("CONSTANTS", "RESOLVER"),
                "network_connection": nat_type,
                "transaction_fee": TRANSACTION_FEE
            }
            mods = []
            try:
                for guid in json.loads(settings[11]):
                    info = self.db.moderators.get_moderator(guid)
                    if info is not None:
                        m = {
                            "guid": guid,
                            "handle": info[4],
                            "name": info[5],
                            "avatar_hash": info[7].encode("hex"),
                            "short_description": info[6],
                            "fee": info[8]
                        }
                        mods.append(m)
            except Exception:
                pass
            settings_json["moderators"] = mods
            request.setHeader('content-type', "application/json")
            request.write(json.dumps(sanitize_html(settings_json), indent=4))
            request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/connected_peers')
    @authenticated
    def get_connected_peers(self, request):
        request.setHeader('content-type', "application/json")
        peers = self.protocol.keys()
        resp = {
            "num_peers": len(peers),
            "peers": peers
        }
        request.write(json.dumps(sanitize_html(resp), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/routing_table')
    @authenticated
    def get_routing_table(self, request):
        nodes = []
        for bucket in self.kserver.protocol.router.buckets:
            for node in bucket.nodes.values():
                n = {
                    "guid": node.id.encode("hex"),
                    "ip": node.ip,
                    "port": node.port,
                    "vendor": node.vendor,
                    "nat_type": objects.NATType.Name(node.nat_type)
                }
                nodes.append(n)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(sanitize_html(nodes), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_notifications')
    @authenticated
    def get_notifications(self, request):
        limit = int(request.args["limit"][0]) if "limit" in request.args else 20
        start = request.args["start"][0] if "start" in request.args else ""
        notifications = self.db.notifications.get_notifications(start, limit)
        notification_dict = {
            "unread": self.db.notifications.get_unread_count(),
            "notifications": []
        }
        for n in notifications[::-1]:
            notification_json = {
                "id": n[0],
                "guid": n[1],
                "handle": n[2],
                "type": n[3],
                "order_id": n[4],
                "title": n[5],
                "timestamp": n[6],
                "image_hash": n[7].encode("hex"),
                "read": False if n[8] == 0 else True
            }
            notification_dict["notifications"].append(notification_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(sanitize_html(notification_dict), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/mark_notification_as_read')
    @authenticated
    def mark_notification_as_read(self, request):
        try:
            for notif_id in request.args["id"]:
                self.db.notifications.mark_as_read(notif_id)
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/broadcast')
    @authenticated
    def broadcast(self, request):
        try:
            def get_response(num):
                request.write(json.dumps({"success": True, "peers reached": num}, indent=4))
                request.finish()
            self.mserver.broadcast(request.args["message"][0]).addCallback(get_response)
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/get_chat_messages')
    @authenticated
    def get_chat_messages(self, request):
        start = request.args["start"][0] if "start" in request.args else None
        messages = self.db.messages.get_messages(request.args["guid"][0], "CHAT", start)
        message_list = []
        for m in messages[::-1]:
            message_json = {
                "id": m[11],
                "guid": m[0],
                "handle": m[1],
                "message": m[5],
                "timestamp": m[6],
                "avatar_hash": m[7].encode("hex"),
                "outgoing": False if m[9] == 0 else True,
                "read": False if m[10] == 0 else True
            }
            message_list.append(message_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(sanitize_html(message_list), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_chat_conversations')
    @authenticated
    def get_chat_conversations(self, request):
        messages = self.db.messages.get_conversations()
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(messages, indent=4).encode("utf-8"))
        request.finish()
        return server.NOT_DONE_YET

    @DELETE('^/api/v1/chat_conversation')
    @authenticated
    def delete_conversations(self, request):
        try:
            self.db.messages.delete_messages(request.args["guid"][0])
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/mark_chat_message_as_read')
    @authenticated
    def mark_chat_message_as_read(self, request):
        try:
            self.db.messages.mark_as_read(request.args["guid"][0])
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/get_sales')
    @authenticated
    def get_sales(self, request):
        sales = self.db.sales.get_all()
        sales_list = []
        for sale in sales:
            sale_json = {
                "order_id": sale[0],
                "title": sale[1],
                "description": sale[2],
                "timestamp": sale[3],
                "btc_total": sale[4],
                "status": sale[5],
                "thumbnail_hash": sale[6],
                "buyer": sale[7],
                "contract_type": sale[8]
            }
            sales_list.append(sale_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(sanitize_html(sales_list), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_purchases')
    @authenticated
    def get_purchases(self, request):
        purchases = self.db.purchases.get_all()
        purchases_list = []
        for purchase in purchases:
            purchase_json = {
                "order_id": purchase[0],
                "title": purchase[1],
                "description": purchase[2],
                "timestamp": purchase[3],
                "btc_total": purchase[4],
                "status": purchase[5],
                "thumbnail_hash": purchase[6],
                "vendor": purchase[7],
                "contract_type": purchase[8]
            }
            purchases_list.append(purchase_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(sanitize_html(purchases_list), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/check_for_payment')
    @authenticated
    def check_for_payment(self, request):
        if not self.protocol.blockchain.connected:
            request.write(json.dumps({"success": False, "reason": "libbitcoin server offline"}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        try:
            check_order_for_payment(request.args["order_id"][0], self.db,
                                    self.protocol.blockchain,
                                    self.mserver.protocol.get_notification_listener(),
                                    self.protocol.testnet)
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/get_order')
    @authenticated
    def get_order(self, request):
        #TODO: if this is either a funded direct payment sale or complete moderated sale but
        #TODO: the payout tx has not hit the blockchain, rebroadcast.

        filename = request.args["order_id"][0] + ".json"
        if os.path.exists(os.path.join(DATA_FOLDER, "purchases", "unfunded", filename)):
            file_path = os.path.join(DATA_FOLDER, "purchases", "unfunded", filename)
            status = self.db.purchases.get_status(request.args["order_id"][0])
        elif os.path.exists(os.path.join(DATA_FOLDER, "purchases", "in progress", filename)):
            file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", filename)
            status = self.db.purchases.get_status(request.args["order_id"][0])
        elif os.path.exists(os.path.join(DATA_FOLDER, "purchases", "trade receipts", filename)):
            file_path = os.path.join(DATA_FOLDER, "purchases", "trade receipts", filename)
            status = self.db.purchases.get_status(request.args["order_id"][0])
        elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", filename)):
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", filename)
            status = self.db.sales.get_status(request.args["order_id"][0])
        elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "in progress", filename)):
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", filename)
            status = self.db.sales.get_status(request.args["order_id"][0])
        elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "trade receipts", filename)):
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "trade receipts", filename)
            status = self.db.sales.get_status(request.args["order_id"][0])
        elif os.path.exists(os.path.join(DATA_FOLDER, "cases", filename)):
            file_path = os.path.join(DATA_FOLDER, "cases", filename)
            status = 4
        else:
            request.write(json.dumps({}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

        with open(file_path, 'r') as filename:
            order = json.load(filename, object_pairs_hook=OrderedDict)

        if status == 0 or status == 2:
            check_order_for_payment(request.args["order_id"][0], self.db, self.protocol.blockchain,
                                    self.mserver.protocol.get_notification_listener(),
                                    self.protocol.testnet)

        def return_order():
            request.setHeader('content-type', "application/json")
            request.write(json.dumps(sanitize_html(order), indent=4))
            request.finish()

        def height_fetched(ec, chain_height):
            payment_address = order["buyer_order"]["order"]["payment"]["address"]
            txs = []
            def history_fetched(ec, history):
                if ec:
                    return_order()
                elif timeout.active():
                    timeout.cancel()
                    for tx_type, txid, i, height, value in history:  # pylint: disable=W0612
                        tx = {
                            "txid": txid.encode("hex"),
                            "value": round(float(value) / 100000000, 8),
                            "confirmations": chain_height - height + 1 if height != 0 else 0
                        }

                        if tx_type == obelisk.PointIdent.Output:
                            tx["type"] = "incoming"
                        else:
                            tx["type"] = "outgoing"
                        txs.append(tx)
                    order["bitcoin_txs"] = txs
                    request.setHeader('content-type', "application/json")
                    request.write(json.dumps(order, indent=4))
                    request.finish()
            self.protocol.blockchain.fetch_history2(payment_address, history_fetched)

        if self.protocol.blockchain.connected:
            self.protocol.blockchain.fetch_last_height(height_fetched)
            timeout = reactor.callLater(4, return_order)
        else:
            return_order()
        return server.NOT_DONE_YET

    @POST('^/api/v1/dispute_contract')
    @authenticated
    def dispute_contract(self, request):
        try:
            self.mserver.open_dispute(request.args["order_id"][0],
                                      request.args["claim"][0].decode("utf8") if "claim" in request.args else None)
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/close_dispute')
    @authenticated
    def close_dispute(self, request):
        try:
            def cb(resp):
                if resp:
                    request.write(json.dumps({"success": True}, indent=4))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": resp}, indent=4))
                    request.finish()

            d = self.mserver.close_dispute(request.args["order_id"][0],
                                           request.args["resolution"][0].decode("utf8")
                                           if "resolution" in request.args else None,
                                           request.args["buyer_percentage"][0]
                                           if "buyer_percentage" in request.args else None,
                                           request.args["vendor_percentage"][0]
                                           if "vendor_percentage" in request.args else None,
                                           request.args["moderator_percentage"][0]
                                           if "moderator_percentage" in request.args else None,
                                           request.args["moderator_address"][0]
                                           if "moderator_address" in request.args else None)

            d.addCallback(cb)
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/release_funds')
    @authenticated
    def release_funds(self, request):
        try:
            self.mserver.release_funds(request.args["order_id"][0])
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/get_cases')
    @authenticated
    def get_cases(self, request):
        cases = self.db.cases.get_all()
        cases_list = []
        for case in cases:
            purchase_json = {
                "order_id": case[0],
                "title": case[1],
                "timestamp": case[2],
                "order_date": case[3],
                "btc_total": case[4],
                "thumbnail_hash": case[5],
                "buyer": case[6],
                "vendor": case[7],
                "validation": json.loads(case[8]),
                "status": "closed" if case[10] == 1 else "open"
            }
            cases_list.append(purchase_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(sanitize_html(cases_list), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/order_messages')
    @authenticated
    def order_messages(self, request):
        message_list = []
        messages = self.db.messages.get_order_messages(request.args["order_id"][0])
        for m in messages:
            if m[0] is not None:
                message_json = {
                    "guid": m[0],
                    "handle": m[1],
                    "message": m[5],
                    "timestamp": m[6],
                    "avatar_hash": m[7].encode("hex"),
                    "message_type": m[4],
                    "outgoing": False if m[9] == 0 else True
                }
                message_list.append(message_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(sanitize_html(message_list), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_ratings')
    @authenticated
    def get_ratings(self, request):
        def parse_response(ratings):
            if ratings is not None:
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(sanitize_html(ratings), indent=4))
                request.finish()
            else:
                request.write(json.dumps({}))
                request.finish()
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    if "contract_id" in request.args and request.args["contract_id"][0] != "":
                        self.mserver.get_ratings(node, unhexlify(request.args["contract_id"][0]))\
                            .addCallback(parse_response)
                    else:
                        self.mserver.get_ratings(node).addCallback(parse_response)
                else:
                    request.write(json.dumps({}))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            ratings = []
            if "contract_id" in request.args and request.args["contract_id"][0] != "":
                for rating in self.db.ratings.get_listing_ratings(request.args["contract_id"][0]):
                    ratings.append(json.loads(rating[0]))
            else:
                for rating in self.db.ratings.get_all_ratings():
                    ratings.append(json.loads(rating[0]))
            request.setHeader('content-type', "application/json")
            request.write(json.dumps(sanitize_html(ratings), indent=4))
            request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/btc_price')
    @authenticated
    def btc_price(self, request):
        request.setHeader('content-type', "application/json")
        if "currency" in request.args:
            try:
                result = BtcPrice.instance().get(request.args["currency"][0].upper(), False)
                request.write(json.dumps({"btcExchange":result, "currencyCodes":BtcPrice.instance().prices}))
                request.finish()
                return server.NOT_DONE_YET
            except KeyError:
                pass
        request.write(json.dumps({"currencyCodes": BtcPrice.instance().prices}))
        request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/refund')
    @authenticated
    def refund(self, request):
        try:
            def respond(success):
                if success is True:
                    request.write(json.dumps({"success": True}))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": success}))
                    request.finish()
            self.mserver.refund(request.args["order_id"][0]).addCallback(respond)
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET


class RestAPI(Site):

    def __init__(self, mserver, kserver, openbazaar_protocol, username, password,
                 authenticated_sessions, only_ip=None, timeout=60 * 60 * 1):
        if only_ip == None:
            only_ip = ["127.0.0.1"]
        self.only_ip = only_ip
        api_resource = OpenBazaarAPI(mserver, kserver, openbazaar_protocol,
                                     username, password, authenticated_sessions)
        Site.__init__(self, api_resource, timeout=timeout)

    def buildProtocol(self, addr):
        if addr.host not in self.only_ip and "0.0.0.0" not in self.only_ip:
            return
        return Site.buildProtocol(self, addr)
