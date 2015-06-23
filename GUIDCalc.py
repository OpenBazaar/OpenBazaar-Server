__author__ = 'chris'
import hashlib, binascii, pyelliptic, bitcoin, time

threshold_hex = "0003FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
reputation_threshold = long(threshold_hex, 16)
reputation_score = long(threshold_hex, 16) + 1

h = hashlib.sha512()
start = time.time()
while reputation_score > reputation_threshold:
    keypair = pyelliptic.ECC(curve="secp256k1")
    pubkey = keypair.get_pubkey()
    bin_key = bitcoin.decode_pubkey(binascii.hexlify(pubkey), "hex")
    hex_key = bitcoin.encode_pubkey(bin_key, "hex_compressed")
    signature = keypair.sign(hex_key)
    h.update(hex_key + binascii.hexlify(signature))
    reputation_score = long(binascii.hexlify(h.digest())[64:], 16)

print "Found GUID in %s seconds" % (time.time() - start)