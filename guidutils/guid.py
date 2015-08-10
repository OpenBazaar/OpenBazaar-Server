__author__ = 'chris'
import nacl.signing
import nacl.hash
import guidc

from binascii import hexlify, unhexlify


class GUID(object):
    def __init__(self, use_C_lib=False):
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

    def __str__(self):
        return "privkey: %s\nsigned pubkey: %s\nguid: %s" % (hexlify(self.privkey), hexlify(self.signed_pubkey), hexlify(self.guid))
