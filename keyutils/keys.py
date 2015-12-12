__author__ = 'chris'
import json
import time
import bitcoin
import nacl.signing
import nacl.encoding
from keyutils.guid import GUID
from nacl.public import PrivateKey
from txrestapi.resource import APIResource
from txrestapi.methods import GET
from twisted.web import server
from twisted.internet.defer import Deferred
from twisted.web.server import Site
from twisted.internet import reactor


class KeyChain(object):

    def __init__(self, database):
        self.db = database.KeyStore()
        guid_keys = self.db.get_key("guid")
        if guid_keys is None:
            self.create_keychain()
        else:
            g = GUID.from_privkey(guid_keys[0])
            self.guid = g.guid
            self.guid_privkey = g.privkey
            self.signing_key = nacl.signing.SigningKey(self.guid_privkey)
            self.guid_signed_pubkey = g.signed_pubkey
            # pylint: disable=W0633
            self.bitcoin_master_privkey, self.bitcoin_master_pubkey = self.db.get_key("bitcoin")
            self.encryption_key = PrivateKey(self.guid_privkey)
            self.encryption_pubkey = self.encryption_key.public_key.encode()

    def create_keychain(self):
        """
        The guid generation can take a while. While it's doing that we will
        open a port to allow a UI to connect and listen for generation to
        complete.
        """
        print "Generating GUID, this may take a few minutes..."
        d = Deferred()
        api = GUIDGenerationListener(d)
        site = Site(api, timeout=None)
        connector = reactor.listenTCP(18470, site, interface="127.0.0.1")
        start = time.time()
        g = GUID()
        d.callback((round(time.time() - start, 2), connector))

        self.guid = g.guid
        self.guid_privkey = g.privkey
        self.signing_key = nacl.signing.SigningKey(self.guid_privkey)
        self.guid_signed_pubkey = g.signed_pubkey
        self.db.set_key("guid", self.guid_privkey, self.guid_signed_pubkey)

        self.bitcoin_master_privkey = bitcoin.bip32_master_key(bitcoin.sha256(self.guid_privkey))
        self.bitcoin_master_pubkey = bitcoin.bip32_privtopub(self.bitcoin_master_privkey)
        self.db.set_key("bitcoin", self.bitcoin_master_privkey, self.bitcoin_master_pubkey)

        self.encryption_key = PrivateKey(self.guid_privkey)
        self.encryption_pubkey = self.encryption_key.public_key.encode()


class GUIDGenerationListener(APIResource):

    def __init__(self, deffered):
        self.defferred = deffered
        APIResource.__init__(self)

    @GET('^/api/v1/guid_generation')
    def guid_generation(self, request):
        """
        A long polling GET which returns when the guid creation is finished.
        """
        def notify(resp):
            request.write(json.dumps({"success": True, "GUID generation time": resp[0]}, indent=4))
            request.finish()
            resp[1].stopListenting()
        self.defferred.addCallback(notify)
        return server.NOT_DONE_YET
