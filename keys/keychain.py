__author__ = 'chris'
import bitcointools
import nacl.signing
import nacl.encoding
import threading
from keys.guid import GUID


class KeyChain(object):

    def __init__(self, database, callback=None, heartbeat_server=None):
        self.db = database
        guid_keys = self.db.keys.get_key("guid")
        if guid_keys is None:
            if heartbeat_server:
                heartbeat_server.set_status("generating GUID")
            threading.Thread(target=self.create_keychain, args=[callback]).start()
        else:
            g = GUID.from_privkey(guid_keys[0])
            self.guid = g.guid
            self.signing_key = g.signing_key
            self.verify_key = g.verify_key
            # pylint: disable=W0633
            self.bitcoin_master_privkey, self.bitcoin_master_pubkey = self.db.keys.get_key("bitcoin")
            self.encryption_key = self.signing_key.to_curve25519_private_key()
            self.encryption_pubkey = self.verify_key.to_curve25519_public_key()
            if callable(callback):
                callback(self)

    def create_keychain(self, callback=None):
        """
        The guid generation can take a while. While it's doing that we will
        open a port to allow a UI to connect and listen for generation to
        complete.
        """
        print "Generating GUID, this may take a few minutes..."
        g = GUID()
        self.guid = g.guid
        self.signing_key = g.signing_key
        self.verify_key = g.verify_key
        self.db.keys.set_key("guid", self.signing_key.encode(encoder=nacl.encoding.HexEncoder),
                             self.verify_key.encode(encoder=nacl.encoding.HexEncoder))

        self.bitcoin_master_privkey = bitcointools.bip32_master_key(bitcointools.sha256(self.signing_key.encode()))
        self.bitcoin_master_pubkey = bitcointools.bip32_privtopub(self.bitcoin_master_privkey)
        self.db.keys.set_key("bitcoin", self.bitcoin_master_privkey, self.bitcoin_master_pubkey)

        self.encryption_key = self.signing_key.to_curve25519_private_key()
        self.encryption_pubkey = self.verify_key.to_curve25519_public_key()
        if callable(callback):
            callback(self, True)
