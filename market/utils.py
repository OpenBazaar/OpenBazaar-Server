import bitcointools
import binascii
import re


def deserialize(tx):
    """
    The pybitcointools deserialize function doesn't display the output index so we can't use it
    to get the tx outpoint since the dictionary might not keep the same order.
    """

    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        # pylint: disable=W0108
        return bitcointools.json_changebase(deserialize(binascii.unhexlify(tx)),
                                            lambda x: bitcointools.safe_hexlify(x))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object
    # so that it is call-by-reference
    pos = [0]

    def read_as_int(bytez):
        pos[0] += bytez
        return bitcointools.decode(tx[pos[0]-bytez:pos[0]][::-1], 256)

    def read_var_int():
        pos[0] += 1

        val = bitcointools.from_byte_to_int(tx[pos[0]-1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0]-bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4)
    ins = read_var_int()
    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": read_var_string(),
            "index": i
        })
    obj["locktime"] = read_as_int(4)
    return obj
