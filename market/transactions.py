__author__ = 'chris'

import struct
import bitcointools
from bitcoin import SelectParams
from bitcoin.core import x, lx, b2x, b2lx, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction
from bitcoin.core.script import CScript, SIGHASH_ALL, SignatureHash, OP_0
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from config import TRANSACTION_FEE
from io import BytesIO
from log import Logger


class BitcoinTransaction(object):
    """
    A Bitcoin transaction object which is used for building, signing, and broadcasting
    Bitcoin transactions. It is designed primarily to take in a list of outpoints
    (all paid to the same address) and payout to a single address. At present this is the
    only way we make transactions in OpenBazaar so more advanced functionality is not needed.
    """
    def __init__(self, tx, testnet=False):
        """
        Create a new transaction

        Args:
            tx: a `CMutableTransaction` object
        """
        SelectParams("testnet" if testnet else "mainnet")
        self.tx = tx
        self.log = Logger(system=self)

    @classmethod
    def make_unsigned(cls, outpoints, output_address, tx_fee=TRANSACTION_FEE, testnet=False, out_value=None):
        """
        Build an unsigned transaction.

        Args:
            outpoints: A `list` of `dict` objects which contain a txid, vout, value, and scriptPubkey.
            output_address: The address to send the full value (minus the tx fee) of the inputs to.
            tx_fee: The Bitcoin network fee to be paid on this transaction.
            testnet: Should this transaction be built for testnet?
            out_value: used if you want to specify a specific output value otherwise the full value
                of the inputs (minus the tx fee) will be used.
        """
        # build the inputs from the outpoints object
        SelectParams("testnet" if testnet else "mainnet")
        txins = []
        in_value = 0
        for outpoint in outpoints:
            in_value += outpoint["value"]
            txin = CMutableTxIn(COutPoint(lx(outpoint["txid"]), outpoint["vout"]))
            txin.scriptSig = CScript(x(outpoint["scriptPubKey"]))
            txins.append(txin)

        # build the output
        value = out_value if out_value is not None else (in_value - tx_fee)
        txout = CMutableTxOut(value, CBitcoinAddress(output_address).to_scriptPubKey())

        # make the transaction
        tx = CMutableTransaction(txins, [txout])

        return BitcoinTransaction(tx)

    @classmethod
    def from_serialized(cls, serialized_tx, testnet=False):
        tx = CMutableTransaction.stream_deserialize(BytesIO(serialized_tx))
        return BitcoinTransaction(tx, testnet)

    def sign(self, privkey):
        """
        Sign each of the inputs with the private key. Inputs should all be sent to
        the same scriptPubkey so we should only need one key.
        """
        seckey = CBitcoinSecret.from_secret_bytes(x(bitcointools.encode_privkey(privkey, "hex")))

        for i in range(len(self.tx.vin)):
            txin_scriptPubKey = self.tx.vin[i].scriptSig
            sighash = SignatureHash(txin_scriptPubKey, self.tx, i, SIGHASH_ALL)
            sig = seckey.sign(sighash) + struct.pack('<B', SIGHASH_ALL)
            self.tx.vin[i].scriptSig = CScript([sig, seckey.pub])

            VerifyScript(self.tx.vin[i].scriptSig, txin_scriptPubKey, self.tx, i, (SCRIPT_VERIFY_P2SH,))

    def create_signature(self, privkey, reedem_script):
        """
        Exports a raw signature suitable for use in a multisig transaction
        """
        seckey = CBitcoinSecret.from_secret_bytes(x(bitcointools.encode_privkey(privkey, "hex")))
        signatures = []
        for i in range(len(self.tx.vin)):
            sighash = SignatureHash(CScript(x(reedem_script)), self.tx, i, SIGHASH_ALL)
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
            self.tx.vin[i].scriptSig = CScript([OP_0, x(s[0]), x(s[1]), CScript(x(redeem_script))])
            try:
                VerifyScript(self.tx.vin[i].scriptSig, CScript(x(redeem_script)).to_p2sh_scriptPubKey(),
                             self.tx, i, (SCRIPT_VERIFY_P2SH,))
                return True
            except Exception:
                return False

    def to_raw_tx(self):
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
        libbitcoin_client.broadcast(self.to_raw_tx())
        self.log.info("Broadcasting payout tx %s to network" % b2lx(self.tx.GetHash()))

    def check_for_funding(self, address):
        """
        Check to see if any of the outputs pay the given address

        Args:
            address: base58check encoded bitcoin address

        Returns: a `list` of `dict` outpoints if any of the outputs match
            the address else None.
        """

        outpoints = []
        for i in range(len(self.tx.vout)):
            addr = CBitcoinAddress.from_scriptPubKey(self.tx.vout[i].scriptPubKey)
            if str(addr) == address:
                o = {
                    "txid": b2lx(self.tx.GetHash()),
                    "vout": i,
                    "value": self.tx.vout[i].nValue,
                    "scriptPubKey": self.tx.vout[i].scriptPubKey.encode("hex")
                }
                outpoints.append(o)
        return outpoints if len(outpoints) > 0 else None

    def get_out_value(self):
        value = 0
        for out in self.tx.vout:
            value += out.nValue
        return value

    def get_hash(self):
        return b2lx(self.tx.GetHash())

    def __repr__(self):
        return repr(self.tx)
