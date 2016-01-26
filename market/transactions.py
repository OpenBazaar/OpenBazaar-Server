__author__ = 'chris'

import struct
from binascii import unhexlify
from bitcoin import SelectParams
from bitcoin.core import x, lx, b2x, b2lx, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction
from bitcoin.core.script import CScript, SIGHASH_ALL, SignatureHash
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from constants import TRANSACTION_FEE
from io import BytesIO
from log import Logger


class BitcoinTransaction(object):
    """
    A Bitcoin transaction object which is used for building, signing, and broadcasting
    Bitcoin transactions. It is designed primarily to take in a list of outpoints
    (all paid to the same address) and payout to a single address. At present this is the
    only way we make transactions in OpenBazaar so more advanced functionality is not needed.
    """
    def __init__(self, tx):
        """
        Create a new transaction

        Args:
            tx: a `CMutableTransaction` object
        """
        self.tx = tx
        self.log = Logger(system=self)

    @classmethod
    def make_unsigned(cls, outpoints, output_address, tx_fee=TRANSACTION_FEE, testnet=False):
        """
        Build an unsigned transaction.

        Args:
            outpoints: A `list` of `dict` objects which contain a txid, vout, value, and scriptPubkey.
            output_address: The address to send the full value (minus the tx fee) of the inputs to.
            tx_fee: The Bitcoin network fee to be paid on this transaction.
            testnet: Should this transaction be built for testnet?
        """
        SelectParams("testnet" if testnet else "mainnet")

        # build the inputs from the outpoints object
        txins = []
        in_value = 0
        for outpoint in outpoints:
            in_value += outpoint["value"]
            txin = CMutableTxIn(COutPoint(lx(outpoint["txid"]), outpoint["vout"]))
            txin.scriptSig = CScript(x(outpoint["scriptPubKey"]))
            txins.append(txin)

        # build the output
        txout = CMutableTxOut(in_value - tx_fee, CBitcoinAddress(output_address).to_scriptPubKey())

        # make the transaction
        tx = CMutableTransaction(txins, [txout])

        return BitcoinTransaction(tx)

    @classmethod
    def from_serialized(cls, serialized_tx):
        tx = CMutableTransaction.stream_deserialize(BytesIO(serialized_tx))
        return BitcoinTransaction(tx)

    def sign(self, privkey):
        """
        Sign each of the inputs with the private key. Inputs should all be sent to
        the same scriptPubkey so we should only need one key.
        """
        seckey = CBitcoinSecret.from_secret_bytes(unhexlify(privkey))

        for i in range(len(self.tx.vin)):
            txin_scriptPubKey = self.tx.vin[i].scriptSig
            sighash = SignatureHash(txin_scriptPubKey, self.tx, i, SIGHASH_ALL)
            sig = seckey.sign(sighash) + struct.pack('<B', SIGHASH_ALL)
            self.tx.vin[i].scriptSig = CScript([sig, seckey.pub])

            VerifyScript(self.tx.vin[i].scriptSig, txin_scriptPubKey, self.tx, i, (SCRIPT_VERIFY_P2SH,))

    def create_signature(self, privkey):
        """
        Exports a raw signature suitable for use in a multisig transaction
        """
        seckey = CBitcoinSecret.from_secret_bytes(unhexlify(privkey))
        signatures = []
        for i in range(len(self.tx.vin)):
            txin_scriptPubKey = self.tx.vin[i].scriptSig
            sighash = SignatureHash(txin_scriptPubKey, self.tx, i, SIGHASH_ALL)
            signatures.append({
                "index": i,
                "signature": (seckey.sign(sighash) + struct.pack('<B', SIGHASH_ALL)).encode("hex")
            })
        return signatures

    def multisign(self, sigs, redeem_script):
        """
        Signs a multisig transaction.

        Args:
            sigs: a `list` of `dict` with format: {"index": 0, "signatures": [sig1, sig2]}
            redeem_script: the redeem script in hex

        """
        for sig in sigs:
            i = sig["index"]
            s = sig["signatures"]
            self.tx.vin[i].scriptSig = CScript([unhexlify(s[0]), unhexlify(s[1]), CScript(x(redeem_script))])
            VerifyScript(self.tx.vin[i].scriptSig,
                         CScript(x(redeem_script)).to_p2sh_scriptPubKey(), self.tx, i, (SCRIPT_VERIFY_P2SH,))

    def get_raw_tx(self):
        """
        return the raw, serialized transaction
        """
        return b2x(self.tx.serialize())

    def broadcast(self, libbitcoin_client):
        """
        Broadcast the tx to the network

        Args:
            libbitcoin_server: an `obelisk.Libbitcoin_client` object.
        """
        libbitcoin_client.broadcast(self.get_raw_tx())
        self.log.info("Broadcasting payout tx %s to network" % b2lx(self.tx.GetHash()))

    def get_outpoints(self):
        """Get a list of deserialized outpoints"""
        outpoints = []
        for i in range(len(self.tx.vout)):
            o = {
                "txid": b2lx(self.tx.GetHash()),
                "index": i,
                "value": self.tx.vout[i].nValue,
                "scriptPubKey": self.tx.vout[i].scriptPubKey.encode("hex")
            }
            outpoints.append(o)
        return outpoints

    def __repr__(self):
        return repr(self.tx)
