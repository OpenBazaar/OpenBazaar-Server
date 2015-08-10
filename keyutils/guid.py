__author__ = 'chris'
import nacl.signing
import nacl.hash
import guidc
from binascii import hexlify, unhexlify

class GUID(object):
    def __init__(self, privkey=None, use_C_lib=False):
        if privkey is None:
            if use_C_lib:
                self.privkey = unhexlify(guidc.generate())
                self.signing_key = nacl.signing.SigningKey(self.privkey)
                verify_key = self.signing_key.verify_key
                signed = self.signing_key.sign(str(verify_key))
                h = nacl.hash.sha512(signed)
                self.signed_pubkey = signed
                self.guid = unhexlify(h[:40])
            else:
                self.privkey = self.generate()
        else:
            self.from_privkey(privkey)

    def generate(self):
        def testpow(pow):
            return True if int(pow, 16) < 50 else False

        valid_pow = False
        while not valid_pow:
            signing_key = nacl.signing.SigningKey.generate()
            verify_key = signing_key.verify_key
            signed = signing_key.sign(str(verify_key))
            h = nacl.hash.sha512(signed)
            pow = h[64:128]
            valid_pow = testpow(pow[:6])
        self.signing_key = signing_key
        self.guid = unhexlify(h[:40])
        self.signed_pubkey = signed
        return signing_key.encode()

    def from_privkey(self, privkey):
        def testpow(pow):
            return True if int(pow, 16) < 50 else False

        signing_key = nacl.signing.SigningKey(privkey)
        verify_key = signing_key.verify_key
        signed = signing_key.sign(str(verify_key))
        h = nacl.hash.sha512(signed)
        pow = h[64:128]
        if testpow(pow[:6]):
            self.signing_key = signing_key
            self.guid = unhexlify(h[:40])
            self.signed_pubkey = signed
            self.privkey = privkey
            return True
        else:
            return False

    def __str__(self):
        return "privkey: %s\nsigned pubkey: %s\nguid: %s" % (hexlify(self.privkey), hexlify(self.signed_pubkey), hexlify(self.guid))
