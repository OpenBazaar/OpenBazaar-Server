__author__ = 'chris'
import json
import os
from txrestapi.resource import APIResource
from txrestapi.methods import GET
from twisted.web import server
from twisted.web.resource import NoResource
from twisted.web import http
from twisted.internet import defer
from binascii import unhexlify
from constants import DATA_FOLDER
from twisted.protocols.basic import FileSender
from protos.countries import CountryCode
from protos.objects import Profile

DEFAULT_RECORDS_COUNT = 20
DEFAULT_RECORDS_OFFSET = 0


class OpenBazaarAPI(APIResource):
    """
    This RESTful API allows clients to pull relevant data from the
    OpenBazaar daemon for use in a GUI or other application.
    """

    def __init__(self, mserver, kserver):
        self.mserver = mserver
        self.kserver = kserver
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

    @GET('^/api/v1/get_profile')
    def get_profile(self, request):
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    def parse_profile(profile):
                        if profile is not None:
                            profile_json = {
                                "profile": {
                                    "guid": request.args["guid"][0],
                                    "name": profile.name,
                                    "location": str(CountryCode.Name(profile.location)),
                                    "enryption_key": profile.encryption_key.encode("hex"),
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
                                    "pgp_key": profile.pgp_key.publicKey,
                                    "avatar_hash": profile.avatar_hash.encode("hex"),
                                    "header_hash": profile.header_hash.encode("hex"),
                                    "social_accounts": {}
                                }
                            }
                            for account in profile.social:
                                profile_json["profile"]["social_accounts"][str(
                                    Profile.SocialAccount.SocialType.Name(account.type)).lower()] = {
                                        "username": account.username,
                                        "proof_url": account.proof_url
                                    }
                            request.setHeader('content-type', "application/json")
                            request.write(json.dumps(profile_json, indent=4))
                            request.finish()
                        else:
                            request.write(NoResource().render(request))
                            request.finish()
                    self.mserver.get_profile(node).addCallback(parse_profile)
                else:
                    request.write(NoResource().render(request))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            request.write(NoResource().render(request))
            request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_listings')
    def get_listings(self, request):
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    def parse_listings(listings):
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
                    self.mserver.get_listings(node).addCallback(parse_listings)
                else:
                    request.write(NoResource().render(request))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            request.write(NoResource().render(request))
            request.finish()
        return server.NOT_DONE_YET

    @GET('^/api/v1/get_followers')
    def get_followers(self, request):
        if "guid" in request.args:
            def get_node(node):
                if node is not None:
                    def parse_followers(followers):
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
                    self.mserver.get_followers(node).addCallback(parse_followers)
                else:
                    request.write(NoResource().render(request))
                    request.finish()
            self.kserver.resolve(unhexlify(request.args["guid"][0])).addCallback(get_node)
        else:
            request.write(NoResource().render(request))
            request.finish()
        return server.NOT_DONE_YET
