__author__ = 'chris'
import nacl.signing
import nacl.hash


def generate():
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
    return signing_key.encode()