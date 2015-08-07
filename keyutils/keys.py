__author__ = 'chris'
import bitcoin
import nacl.signing
from db.datastore import KeyStore
from guid import GUID

class KeyChain(object):

    def __init__(self):
        self.db = KeyStore()
        guid_keys = self.db.get_key("guid")
        if guid_keys is None:
            self.create_keychain()
        else:
            g = GUID(guid_keys[0])
            self.guid = g.guid
            self.guid_privkey = g.privkey
            self.signing_key = nacl.signing.SigningKey(self.guid_privkey)
            self.guid_signed_pubkey = g.signed_pubkey
            self.bitcoin_master_privkey, self.bitcoin_master_pubkey = self.db.get_key("bitcoin")

    def create_keychain(self):
        print "Generating GUID, stand by..."
        g = GUID()
        self.guid = g.guid
        self.guid_privkey = g.privkey
        self.signing_key = nacl.signing.SigningKey(self.guid_privkey)
        self.guid_signed_pubkey = g.signed_pubkey
        self.db.set_key("guid", self.guid_privkey, self.guid_signed_pubkey)

        self.bitcoin_master_privkey = bitcoin.bip32_master_key(bitcoin.sha256(self.guid_privkey))
        self.bitcoin_master_pubkey = bitcoin.bip32_privtopub(self.bitcoin_master_privkey)
        self.db.set_key("bitcoin", self.bitcoin_master_privkey, self.bitcoin_master_pubkey)