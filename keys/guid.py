__author__ = 'chris'

# pylint: disable=import-error
#import guidc
from binascii import hexlify, unhexlify

import nacl.signing
import nacl.hash
import nacl.encoding

def _testpow(pow_hash):
    return True if int(pow_hash, 16) < 50 else False

class GUID(object):
    """
    Class for generating the guid. It can be generated using C code for a modest
    speed boost but it is currently disabled to make it easier to compile the app.
    """

    # pylint: disable=W0633
    def __init__(self, keys=None, use_C_lib=False):
        if keys is None:
            if use_C_lib:  # disabled for now
                # self.privkey = unhexlify(guidc.generate())
                self.privkey = None
                self.signing_key = nacl.signing.SigningKey(self.privkey)
                self.verify_key = verify_key = self.signing_key.verify_key
                h = nacl.hash.sha512(verify_key.encode())
                self.guid = unhexlify(h[:40])
            else:
                self.generate()
        else:
            self.signing_key, self.verify_key, self.guid = keys

    def generate(self):
        valid_pow = False
        while not valid_pow:
            signing_key = nacl.signing.SigningKey.generate()
            verify_key = signing_key.verify_key
            h = nacl.hash.sha512(verify_key.encode())
            pow_hash = h[40:]
            valid_pow = _testpow(pow_hash[:6])
        self.signing_key = signing_key
        self.verify_key = verify_key
        self.guid = unhexlify(h[:40])

    @classmethod
    def from_privkey(cls, privkey):
        signing_key = nacl.signing.SigningKey(privkey, encoder=nacl.encoding.HexEncoder)
        verify_key = signing_key.verify_key
        h = nacl.hash.sha512(verify_key.encode())
        pow_hash = h[40:]
        if _testpow(pow_hash[:6]):
            return GUID((signing_key, verify_key, unhexlify(h[:40])))

    def __str__(self):
        return "privkey: %s\npubkey: %s\nguid: %s" % (
            self.signing_key.encode(encoder=nacl.encoding.HexEncoder),
            self.verify_key.encode(encoder=nacl.encoding.HexEncoder),
            hexlify(self.guid))
