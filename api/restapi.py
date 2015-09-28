__author__ = 'chris'
import json
import os
from txrestapi.resource import APIResource
from txrestapi.methods import GET, POST, DELETE
from twisted.web import server
from twisted.web.resource import NoResource
from twisted.web import http
from twisted.internet import defer, reactor
from binascii import unhexlify
from constants import DATA_FOLDER
from twisted.protocols.basic import FileSender
from protos.countries import CountryCode
from protos import objects
from keyutils.keys import KeyChain
from dht.utils import digest
from market.profile import Profile
from market.contracts import Contract
from collections import OrderedDict

DEFAULT_RECORDS_COUNT = 20
DEFAULT_RECORDS_OFFSET = 0


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
                yield _setContentDispositionAndSend(image_path, ".jpg", "image/jpeg")
            else:
                request.setResponseCode(http.NOT_FOUND)
                request.write("No such image '%s'" % request.path)
            request.finish()

        if "hash" in request.args:
            if self.db.HashMap().get_file(unhexlify(request.args["hash"][0])) is not None:
                image_path = self.db.HashMap().get_file(unhexlify(request.args["hash"][0]))
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
                        "handle": profile.handle,
                        "about": profile.about,
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
            if not p.get().encryption_key \
                    and "name" not in request.args \
                    and "location" not in request.args:
                request.write(json.dumps({"success": False, "reason": "name or location not included"}, indent=4))
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
                u.nsfw = True
            if "vendor" in request.args:
                u.vendor = True
            if "moderator" in request.args:
                u.moderator = True
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
                with open(DATA_FOLDER + "store/avatar", 'wb') as outfile:
                    outfile.write(request.args["avatar"][0])
                avatar_hash = digest(request.args["avatar"][0])
                self.db.HashMap().insert(avatar_hash, DATA_FOLDER + "store/avatar")
                u.avatar_hash = avatar_hash
            if "header" in request.args:
                with open(DATA_FOLDER + "store/header", 'wb') as outfile:
                    outfile.write(request.args["header"][0])
                header_hash = digest(request.args["header"][0])
                self.db.HashMap().insert(header_hash, DATA_FOLDER + "store/header")
                u.header_hash = header_hash
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
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET

    @POST('^/api/v1/social_accounts')
    def add_social_account(self, request):
        try:
            p = Profile(self.db)
            if "account_type" in request.args and "username" in request.args and "proof" in request.args:
                p.add_social_account(request.args["account_type"][0], request.args["username"][0],
                                     request.args["proof"][0])
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

        if "id" in request.args:
            if "guid" in request.args:
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
                    with open(self.db.HashMap().get_file(unhexlify(request.args["id"][0])), "r") as filename:
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
                True if "nsfw" in request.args else False,
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
                free_shipping=True if "free_shipping" in request.args else False,
                options=options if "options" in request.args else None,
                moderators=request.args["moderators"] if "moderators" in request.args else None)
            for keyword in request.args["keywords"]:
                self.kserver.set(digest(keyword.lower()), c.get_contract_id(),
                                 self.kserver.node.getProto().SerializeToString())
            request.write(json.dumps({"success": True}))
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
                c = Contract(self.db, hash_value=unhexlify(request.args["id"][0]))
                for keyword in c.contract["vendor_offer"]["listing"]["item"]["keywords"]:
                    self.kserver.delete(keyword.lower(), c.get_contract_id(),
                                        self.keychain.signing_key.sign(c.get_contract_id())[:64])
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
                    contract.await_funding(self.protocol.ws, self.protocol.blockchain, resp)
                    request.write(json.dumps({"success": True, "payment_address": payment_address}, indent=4))
                    request.finish()
                else:
                    request.write(json.dumps({"success": False, "reason": "seller rejected contract"}, indent=4))
                    request.finish()
            options = None
            if "options" in request.args:
                options = {}
                for option in request.args["options"]:
                    options[option] = request.args[option]
            c = Contract(self.db, hash_value=unhexlify(request.args["id"][0]), testnet=self.protocol.testnet)
            payment_address = c.\
                add_purchase_info(request.args["quantity"][0],
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
            seller_guid = unhexlify(c.contract["vendor_offer"]["listing"]["id"]["guid"])
            self.kserver.resolve(seller_guid).addCallback(get_node)
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
            file_path = DATA_FOLDER + "store/listings/in progress/" + request.args["id"][0] + ".json"
            with open(file_path, 'r') as filename:
                order = json.load(filename, object_pairs_hook=OrderedDict)
            c = Contract(self.db, contract=order, testnet=self.protocol.testnet)
            c.add_order_confirmation(request.args["payout_address"][0],
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
            for image in request.args["image"]:
                hash_value = digest(image).encode("hex")
                with open(DATA_FOLDER + "store/media/" + hash_value, 'w') as outfile:
                    outfile.write(image)
                self.db.HashMap().insert(digest(image), DATA_FOLDER + "store/media/" + hash_value)
                ret.append(hash_value)
            request.write(json.dumps({"success": True, "image_hashes": ret}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            request.write(json.dumps({"success": False, "reason": e.message}, indent=4))
            request.finish()
            return server.NOT_DONE_YET
