__author__ = 'chris'
import bitcointools
from binascii import unhexlify


def derive_childkey(key, chaincode, prefix=bitcointools.MAINNET_PUBLIC):
    """
    Given a 33 byte public key and 32 byte chaincode (both in hex) derive the first child key.
    """

    master_key = bitcointools.bip32_serialize((prefix, 0, b'\x00'*4, 0,
                                               unhexlify(chaincode), unhexlify(key)))
    child_key = bitcointools.bip32_ckd(master_key, 0)
    return bitcointools.bip32_extract_key(child_key)


