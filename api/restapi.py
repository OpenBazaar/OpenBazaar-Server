__author__ = 'chris'
import json
import time
import os
import pickle
import obelisk
from binascii import unhexlify
from collections import OrderedDict

from txrestapi.resource import APIResource
from txrestapi.methods import GET, POST, DELETE
from twisted.web import server
from twisted.web.resource import NoResource
from twisted.web import http
from twisted.web.server import Site
from twisted.internet import defer, reactor
from twisted.protocols.basic import FileSender

from constants import DATA_FOLDER
from protos.countries import CountryCode
from protos import objects
from keyutils.keys import KeyChain
from dht.utils import digest
from market.profile import Profile
from market.contracts import Contract
from net.upnp import PortMapper

DEFAULT_RECORDS_COUNT = 20
DEFAULT_RECORDS_OFFSET = 0


def str_to_bool(s):
    if s.lower() == 'true':
        return True
    elif s.lower() == 'false':
        return False
    else:
        raise ValueError


class OpenBazaarAPI(APIResource):
    """
    This RESTful API allows clients to pull relevant data from the
    OpenBazaar daemon for use in a GUI or other application.
    """

    def __init__(self, mserver, kserver, protocol):
        self.mserver = mserver
        self.kserver = kserver
        self.protocol = protocol
        self.db = mserver.db
        self.keychain = KeyChain(self.db)
        APIResource.__init__(self)

    @GET('^/api/v1/get_image')
    def get_image(self, request):
        @defer.inlineCallbacks
        def _showImage(resp=None):
            @defer.inlineCallbacks
            def _setContentDispositionAndSend(file_path, extension, content_type):
                request.setHeader('content-disposition', 'filename="%s.%s"' % (file_path, extension))
                request.setHeader('content-type', content_type)

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
            if self.db.HashMap().get_file(request.args["hash"][0]) is not None:
                image_path = self.db.HashMap().get_file(request.args["hash"][0])
            else:
                image_path = DATA_FOLDER + "cache/" + request.args["hash"][0]
            if not os.path.exists(image_path) and "guid" in request.args:
                def get_node(node):
                    if node is not None:
                        self.mserver.get_image(node, unhexlify(request.args["hash"][0])).addCallback(_showImage)
                    else:
                        _showImage()
                self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
            else:
                _showImage()
        else:
            request.write(NoResource().render(request))
            request.finish()

        return server.NOT_DONE_YET

    @GET('^/api/v1/profile')
    def get_profile(self, request):
        def parse_profile(profile):
            if profile is not None:
                profile_json = {
                    "profile": {
                        "name": profile.name,
                        "location": str(CountryCode.Name(profile.location)),
                        "encryption_key": profile.encryption_key.public_key.encode("hex"),
                        "nsfw": profile.nsfw,
                        "vendor": profile.vendor,
                        "moderator": profile.moderator,
                        "moderation_fee": profile.moderation_fee,
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
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(profile_json, indent=4))
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
            parse_profile(Profile(self.db).get())
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_listings')
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
                request.write(json.dumps(response, indent=4))
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
            ser = self.db.ListingsStore().get_proto()
            if ser is not None:
                l = objects.Listings()
                l.ParseFromString(ser)
                parse_listings(l)
            else:
                parse_listings(None)
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_followers')
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
                request.write(json.dumps(response, indent=4))
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
            ser = self.db.FollowData().get_followers()
            if ser is not None:
                f = objects.Followers()
                f.ParseFromString(ser)
                parse_followers(f)
            else:
                parse_followers(None)
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_following')
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
                request.write(json.dumps(response, indent=4))
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
            ser = self.db.FollowData().get_following()
            if ser is not None:
                f = objects.Following()
                f.ParseFromString(ser)
                parse_following(f)
            else:
                parse_following(None)
        return server.NOT_DONE_YET

    @POST('^/api/v1/follow')
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
    def update_profile(self, request):
        try:
            p = Profile(self.db)
            can_update_profile = (p.get().encryption_key or
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
                u.name = request.args["name"][0]
            if "location" in request.args:
                # This needs to be formatted. Either here or from the UI.
                u.location = CountryCode.Value(request.args["location"][0].upper())
            if "handle" in request.args:
                u.handle = request.args["handle"][0]
            if "about" in request.args:
                u.about = request.args["about"][0]
            if "short_description" in request.args:
                u.short_description = request.args["short_description"][0]
            if "nsfw" in request.args:
                u.nsfw = str_to_bool(request.args["nsfw"][0])
            if "vendor" in request.args:
                u.vendor = str_to_bool(request.args["vendor"][0])
            if "moderator" in request.args:
                u.moderator = str_to_bool(request.args["moderator"][0])
            if "moderation_fee" in request.args:
                u.moderation_fee = float(request.args["moderation_fee"][0])
            if "website" in request.args:
                u.website = request.args["website"][0]
            if "email" in request.args:
                u.email = request.args["email"][0]
            if "primary_color" in request.args:
                u.primary_color = int(request.args["primary_color"][0])
            if "secondary_color" in request.args:
                u.secondary_color = int(request.args["secondary_color"][0])
            if "background_color" in request.args:
                u.background_color = int(request.args["background_color"][0])
            if "text_color" in request.args:
                u.text_color = int(request.args["text_color"][0])
            if "avatar" in request.args:
                u.avatar_hash = unhexlify(request.args["avatar"][0])
            if "header" in request.args:
                u.header_hash = unhexlify(request.args["header"][0])
            if "pgp_key" in request.args and "signature" in request.args:
                p.add_pgp_key(request.args["pgp_key"][0], request.args["signature"][0],
                              self.keychain.guid.encode("hex"))
            enc = u.PublicKey()
            enc.public_key = self.keychain.encryption_pubkey
            enc.signature = self.keychain.signing_key.sign(enc.public_key)[:64]
            u.encryption_key.MergeFrom(enc)
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
    def add_social_account(self, request):
        try:
            p = Profile(self.db)
            if "account_type" in request.args and "username" in request.args:
                p.add_social_account(request.args["account_type"][0], request.args["username"][0],
                                     request.args["proof"][0] if "proof" in request.args else None)
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
    def get_contract(self, request):
        def parse_contract(contract):
            if contract is not None:
                request.setHeader('content-type', "application/json")
                request.write(json.dumps(contract, indent=4))
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
                try:
                    with open(DATA_FOLDER + "cache/" + request.args["id"][0], "r") as filename:
                        contract = json.loads(filename.read(), object_pairs_hook=OrderedDict)
                    parse_contract(contract)
                except Exception:
                    self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
            else:
                try:
                    with open(self.db.HashMap().get_file(request.args["id"][0]), "r") as filename:
                        contract = json.loads(filename.read(), object_pairs_hook=OrderedDict)
                    parse_contract(contract)
                except Exception:
                    parse_contract(None)
        else:
            request.write(json.dumps({}))
            request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/contracts')
    def set_contract(self, request):
        try:
            if "options" in request.args:
                options = {}
                for option in request.args["options"]:
                    options[option] = request.args[option]
            c = Contract(self.db)
            c.create(
                str(request.args["expiration_date"][0]),
                request.args["metadata_category"][0],
                request.args["title"][0],
                request.args["description"][0],
                request.args["currency_code"][0],
                request.args["price"][0],
                request.args["process_time"][0],
                str_to_bool(request.args["nsfw"][0]),
                shipping_origin=request.args["shipping_origin"][0] if "shipping_origin" in request.args else None,
                shipping_regions=request.args["ships_to"] if "ships_to" in request.args else None,
                est_delivery_domestic=request.args["est_delivery_domestic"][0]
                if "est_delivery_domestic" in request.args else None,
                est_delivery_international=request.args["est_delivery_international"][0]
                if "est_delivery_international" in request.args else None,
                terms_conditions=request.args["terms_conditions"][0]
                if request.args["terms_conditions"][0] is not "" else None,
                returns=request.args["returns"][0] if request.args["returns"][0] is not "" else None,
                shipping_currency_code=request.args["shipping_currency_code"][0],
                shipping_domestic=request.args["shipping_domestic"][0],
                shipping_international=request.args["shipping_international"][0],
                keywords=request.args["keywords"] if "keywords" in request.args else None,
                category=request.args["category"][0] if request.args["category"][0] is not "" else None,
                condition=request.args["condition"][0] if request.args["condition"][0] is not "" else None,
                sku=request.args["sku"][0] if request.args["sku"][0] is not "" else None,
                images=request.args["images"],
                free_shipping=str_to_bool(request.args["free_shipping"][0]),
                options=options if "options" in request.args else None,
                moderators=request.args["moderators"] if "moderators" in request.args else None)
            for keyword in request.args["keywords"]:
                self.kserver.set(digest(keyword.lower()), c.get_contract_id(),
                                 self.kserver.node.getProto().SerializeToString())
            request.write(json.dumps({"success": True, "id": c.get_contract_id().encode("hex")}))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @DELETE('^/api/v1/contracts')
    def delete_contract(self, request):
        try:
            if "id" in request.args:
                file_path = self.db.HashMap().get_file(request.args["id"][0])
                with open(file_path, 'r') as filename:
                    contract = json.load(filename, object_pairs_hook=OrderedDict)
                c = Contract(self.db, contract=contract)
                if "keywords" in c.contract["vendor_offer"]["listing"]["item"]:
                    for keyword in c.contract["vendor_offer"]["listing"]["item"]["keywords"]:
                        self.kserver.delete(keyword.lower(), c.get_contract_id(),
                                            self.keychain.signing_key.sign(c.get_contract_id())[:64])
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
        try:
            with open(DATA_FOLDER + "cache.pickle", 'r') as f:
                data = pickle.load(f)
            data["shutdown_time"] = time.time()
            with open(DATA_FOLDER + "cache.pickle", 'w') as f:
                pickle.dump(data, f)
        except IOError:
            pass
        PortMapper().clean_my_mappings(self.kserver.node.port)
        self.protocol.shutdown()
        reactor.stop()

    @POST('^/api/v1/make_moderator')
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
    def purchase_contract(self, request):
        try:
            def handle_response(resp, contract):
                if resp:
                    contract.await_funding(self.mserver.protocol.get_notification_listener(),
                                           self.protocol.blockchain, resp)
                    request.write(json.dumps({"success": True, "payment_address": payment[0],
                                              "amount": payment[1],
                                              "order_id": c.get_contract_id().encode("hex")},
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
                                  request.args["ship_to"][0] if "ship_to" in request.args else None,
                                  request.args["address"][0] if "address" in request.args else None,
                                  request.args["city"][0] if "city" in request.args else None,
                                  request.args["state"][0] if "state" in request.args else None,
                                  request.args["postal_code"][0] if "postal_code" in request.args else None,
                                  request.args["country"][0] if "country" in request.args else None,
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
    def confirm_order(self, request):
        try:
            def respond(success):
                if success:
                    request.write(json.dumps({"success": True}))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": "Failed to send order confirmation"}))
                    request.finish()
            file_path = DATA_FOLDER + "store/contracts/in progress/" + request.args["id"][0] + ".json"
            with open(file_path, 'r') as filename:
                order = json.load(filename, object_pairs_hook=OrderedDict)
            c = Contract(self.db, contract=order, testnet=self.protocol.testnet)
            c.add_order_confirmation(self.protocol.blockchain,
                                     request.args["payout_address"][0],
                                     comments=request.args["comments"][0] if "comments" in request.args else None,
                                     shipper=request.args["shipper"][0] if "shipper" in request.args else None,
                                     tracking_number=request.args["tracking_number"][0]
                                     if "tracking_number" in request.args else None,
                                     est_delivery=request.args["est_delivery"][0]
                                     if "est_delivery" in request.args else None,
                                     url=request.args["url"][0] if "url" in request.args else None,
                                     password=request.args["password"][0] if "password" in request.args else None)
            guid = c.contract["buyer_order"]["order"]["id"]["guid"]
            self.mserver.confirm_order(guid, c).addCallback(respond)
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/upload_image')
    def upload_image(self, request):
        try:
            ret = []
            if "image" in request.args:
                for image in request.args["image"]:
                    img = image.decode('base64')
                    hash_value = digest(img).encode("hex")
                    with open(DATA_FOLDER + "store/media/" + hash_value, 'wb') as outfile:
                        outfile.write(img)
                    self.db.HashMap().insert(hash_value, DATA_FOLDER + "store/media/" + hash_value)
                    ret.append(hash_value)
            elif "avatar" in request.args:
                avi = request.args["avatar"][0].decode("base64")
                hash_value = digest(avi).encode("hex")
                with open(DATA_FOLDER + "store/avatar", 'wb') as outfile:
                    outfile.write(avi)
                self.db.HashMap().insert(hash_value, DATA_FOLDER + "store/avatar")
                ret.append(hash_value)
            elif "header" in request.args:
                hdr = request.args["header"][0].decode("base64")
                hash_value = digest(hdr).encode("hex")
                with open(DATA_FOLDER + "store/header", 'wb') as outfile:
                    outfile.write(hdr)
                self.db.HashMap().insert(hash_value, DATA_FOLDER + "store/header")
                ret.append(hash_value)
            request.write(json.dumps({"success": True, "image_hashes": ret}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/complete_order')
    def complete_order(self, request):
        def respond(success):
            if success:
                request.write(json.dumps({"success": True}))
                request.finish()
            else:
                request.write(json.dumps({"success": False, "reason": "Failed to send receipt to vendor"}))
                request.finish()
        file_path = DATA_FOLDER + "purchases/in progress/" + request.args["id"][0] + ".json"
        with open(file_path, 'r') as filename:
            order = json.load(filename, object_pairs_hook=OrderedDict)
        c = Contract(self.db, contract=order, testnet=self.protocol.testnet)
        c.add_receipt(True,
                      self.protocol.blockchain,
                      feedback=request.args["feedback"][0] if "feedback" in request.args else None,
                      quality=request.args["quality"][0] if "quality" in request.args else None,
                      description=request.args["description"][0] if "description" in request.args else None,
                      delivery_time=request.args["delivery_time"][0]
                      if "delivery_time" in request.args else None,
                      customer_service=request.args["customer_service"][0]
                      if "customer_service" in request.args else None,
                      review=request.args["review"][0] if "review" in request.args else "")
        guid = c.contract["vendor_offer"]["listing"]["id"]["guid"]
        self.mserver.complete_order(guid, c).addCallback(respond)
        return server.NOT_DONE_YET

    @POST('^/api/v1/settings')
    def set_settings(self, request):
        try:
            settings = self.db.Settings()
            settings.update(
                request.args["refund_address"][0],
                request.args["currency_code"][0],
                request.args["country"][0],
                request.args["language"][0],
                request.args["time_zone"][0],
                1 if str_to_bool(request.args["notifications"][0]) else 0,
                json.dumps(request.args["shipping_addresses"] if request.args["shipping_addresses"] != "" else []),
                json.dumps(request.args["blocked"] if request.args["blocked"] != "" else []),
                request.args["libbitcoin_server"][0],
                1 if str_to_bool(request.args["ssl"][0]) else 0,
                KeyChain(self.db).guid_privkey.encode("hex"),
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
    def get_settings(self, request):
        settings = self.db.Settings().get()
        if settings is None:
            request.write(json.dumps({}, indent=4))
            request.finish()
        else:
            settings_json = {
                "refund_address": settings[1],
                "currency_code": settings[2],
                "country": settings[3],
                "language": settings[4],
                "time_zone": settings[5],
                "notifications": True if settings[6] == 1 else False,
                "shipping_addresses": json.loads(settings[7]),
                "blocked_guids": json.loads(settings[8]),
                "libbitcoin_server": settings[9],
                "ssl": True if settings[10] == 1 else False,
                "seed": settings[11],
                "terms_conditions": settings[12],
                "refund_policy": settings[13]
            }
            mods = []
            mods_db = self.db.ModeratorStore()
            try:
                for guid in json.loads(settings[14]):
                    info = mods_db.get_moderator(guid)
                    if info is not None:
                        m = {
                            "guid": guid,
                            "handle": info[6],
                            "name": info[7],
                            "avatar_hash": info[9].encode("hex"),
                            "short_description": info[8],
                            "fee": info[10]
                        }
                        mods.append(m)
            except Exception:
                pass
            settings_json["moderators"] = mods
            request.setHeader('content-type', "application/json")
            request.write(json.dumps(settings_json, indent=4))
            request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/connected_peers')
    def get_connected_peers(self, request):
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(self.protocol.keys(), indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/routing_table')
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
        request.write(json.dumps(nodes, indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_notifications')
    def get_notifications(self, request):
        notifications = self.db.NotificationStore().get_notifications()
        limit = int(request.args["limit"][0]) if "limit" in request.args else len(notifications)
        notification_list = []
        for n in notifications[len(notifications) - limit:]:
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
            notification_list.append(notification_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(notification_list, indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/mark_notification_as_read')
    def mark_notification_as_read(self, request):
        try:
            for notif_id in request.args["id"]:
                self.db.NotificationStore().mark_as_read(notif_id)
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/broadcast')
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
    def get_chat_messages(self, request):
        messages = self.db.MessageStore().get_messages(request.args["guid"][0], "CHAT")
        limit = int(request.args["limit"][0]) if "limit" in request.args else len(messages)
        start = int(request.args["start"][0]) if "start" in request.args else 0
        message_list = []
        for m in messages[::-1][start: start + limit]:
            message_json = {
                "guid": m[0],
                "handle": m[1],
                "message": m[6],
                "timestamp": m[7],
                "avatar_hash": m[8].encode("hex"),
                "outgoing": False if m[10] == 0 else True,
                "read": False if m[11] == 0 else True
            }
            message_list.append(message_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(message_list, indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_chat_conversations')
    def get_chat_conversations(self, request):
        messages = self.db.MessageStore().get_conversations()
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(messages, indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/mark_chat_message_as_read')
    def mark_chat_message_as_read(self, request):
        try:
            self.db.MessageStore().mark_as_read(request.args["guid"][0])
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/get_sales')
    def get_sales(self, request):
        sales = self.db.Sales().get_all()
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
        request.write(json.dumps(sales_list, indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_purchases')
    def get_purchases(self, request):
        purchases = self.db.Purchases().get_all()
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
        request.write(json.dumps(purchases_list, indent=4))
        request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/check_for_payment')
    def check_for_payment(self, request):
        if not self.protocol.blockchain.connected:
            request.write(json.dumps({"success": False, "reason": "libbitcoin server offline"}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        try:
            file_path = DATA_FOLDER + "purchases/unfunded/" + request.args["order_id"][0] + ".json"
            with open(file_path, 'r') as filename:
                order = json.load(filename, object_pairs_hook=OrderedDict)
            c = Contract(self.db, contract=order, testnet=self.protocol.testnet)
            self.protocol.blockchain.refresh_connection()
            c.blockchain = self.protocol.blockchain
            c.notification_listener = self.mserver.protocol.get_notification_listener()
            c.is_purchase = True
            addr = c.contract["buyer_order"]["order"]["payment"]["address"]

            def history_fetched(ec, history):
                if not ec:
                    # pylint: disable=W0612
                    # pylint: disable=W0640
                    for objid, txhash, index, height, value in history:
                        def cb_txpool(ec, result):
                            if ec:
                                self.protocol.blockchain.fetch_transaction(txhash, cb_chain)
                            else:
                                c.on_tx_received(None, None, None, None, result)

                        def cb_chain(ec, result):
                            if not ec:
                                c.on_tx_received(None, None, None, None, result)

                        self.protocol.blockchain.fetch_txpool_transaction(txhash, cb_txpool)

            self.protocol.blockchain.fetch_history2(addr, history_fetched)

            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @GET('^/api/v1/get_order')
    def get_order(self, request):
        #TODO: if this is either a funded direct payment sale or complete moderated sale but
        #TODO: the payout tx has not hit the blockchain, rebroadcast.

        if os.path.exists(DATA_FOLDER + "purchases/unfunded/" + request.args["order_id"][0] + ".json"):
            file_path = DATA_FOLDER + "purchases/unfunded/" + request.args["order_id"][0] + ".json"
        elif os.path.exists(DATA_FOLDER + "purchases/in progress/" + request.args["order_id"][0] + ".json"):
            file_path = DATA_FOLDER + "purchases/in progress/" + request.args["order_id"][0] + ".json"
        elif os.path.exists(DATA_FOLDER + "purchases/trade receipts/" + request.args["order_id"][0] + ".json"):
            file_path = DATA_FOLDER + "purchases/trade receipts/" + request.args["order_id"][0] + ".json"
        elif os.path.exists(DATA_FOLDER + "store/contracts/unfunded/" + request.args["order_id"][0] + ".json"):
            file_path = DATA_FOLDER + "store/contracts/unfunded/" + request.args["order_id"][0] + ".json"
        elif os.path.exists(DATA_FOLDER + "store/contracts/in progress/" + request.args["order_id"][0] + ".json"):
            file_path = DATA_FOLDER + "store/contracts/in progress/" + request.args["order_id"][0] + ".json"
        elif os.path.exists(DATA_FOLDER +
                            "store/contracts/trade receipts/" + request.args["order_id"][0] + ".json"):
            file_path = DATA_FOLDER + "store/contracts/trade receipts/" + request.args["order_id"][0] + ".json"
        elif os.path.exists(DATA_FOLDER + "cases/" + request.args["order_id"][0] + ".json"):
            file_path = DATA_FOLDER + "cases/" + request.args["order_id"][0] + ".json"

        with open(file_path, 'r') as filename:
            order = json.load(filename, object_pairs_hook=OrderedDict)

        def height_fetched(ec, chain_height):
            payment_address = order["buyer_order"]["order"]["payment"]["address"]
            txs = []
            def history_fetched(ec, history):
                if ec:
                    print ec
                else:
                    for tx_type, txid, i, height, value in history:  # pylint: disable=W0612
                        tx = {
                            "txid": txid.encode("hex"),
                            "value": round(float(value) / 100000000, 8),
                            "confirmaions": chain_height - height + 1 if height != 0 else 0
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
        else:
            request.setHeader('content-type', "application/json")
            request.write(json.dumps(order, indent=4))
            request.finish()
        return server.NOT_DONE_YET

    @POST('^/api/v1/dispute_contract')
    def dispute_contract(self, request):
        try:
            self.mserver.open_dispute(request.args["order_id"][0], request.args["claim"][0])
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/close_dispute')
    def close_dispute(self, request):
        try:
            self.mserver.close_dispute(request.args["order_id"][0],
                                       request.args["resolution"][0],
                                       request.args["buyer_percentage"][0],
                                       request.args["vendor_percentage"][0],
                                       request.args["moderator_percentage"][0],
                                       request.args["moderator_address"][0])
            request.write(json.dumps({"success": True}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/release_funds')
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
    def get_cases(self, request):
        cases = self.db.Cases().get_all()
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
                "validation": case[8],
                "status": "closed" if cases[10] == 1 else "open"
            }
            cases_list.append(purchase_json)
        request.setHeader('content-type', "application/json")
        request.write(json.dumps(cases_list, indent=4))
        request.finish()
        return server.NOT_DONE_YET


class RestAPI(Site):

    def __init__(self, mserver, kserver, openbazaar_protocol, only_ip="127.0.0.1", timeout=60 * 60 * 1):
        self.only_ip = only_ip
        api_resource = OpenBazaarAPI(mserver, kserver, openbazaar_protocol)
        Site.__init__(self, api_resource, timeout=timeout)

    def buildProtocol(self, addr):
        if addr.host != self.only_ip and self.only_ip != "0.0.0.0":
            return
        return Site.buildProtocol(self, addr)
