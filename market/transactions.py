__author__ = 'chris'

import struct
from binascii import unhexlify
from bitcoin import SelectParams
from bitcoin.core import b2x, b2lx, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from constants import TRANSACTION_FEE
from log import Logger


class BitcoinTransaction(object):
    """
    A Bitcoin transaction objected which is used for building, signing, and broadcasting
    Bitcoin transactions. It is designed primarily to take in a list of outpoints
    (all paid to the same address) and payout to a single address. At present this is the
    only way we make transactions in OpenBazaar so more advanced functionality is not needed.
    """

    def __init__(self, outpoints, output_address, tx_fee=TRANSACTION_FEE, testnet=False):
        """
        Build the unsigned transaction.

        Args:
            outpoints: A `list` of `dict` objects which contain a txid, vout, and value.
            output_address: The address to send the full value (minus the tx fee) of the inputs to.
            tx_fee: The Bitcoin network fee to be paid on this transaction.
        """
        SelectParams("testnet" if testnet else "mainnet")
        self.log = Logger(system=self)

        # build the inputs from the outpoints object
        txins = []
        in_value = 0
        self.outpoints = outpoints
        for outpoint in outpoints:
            in_value += outpoint["value"]
            txin = CMutableTxIn(COutPoint(outpoint["txid"], outpoint["vout"]))
            txins.append(txin)

        # build the output
        txout = CMutableTxOut(in_value - tx_fee, CBitcoinAddress(output_address).to_scriptPubKey())

        # make the transaction
        self.tx = CMutableTransaction(txins, [txout])

    def sign(self, priv_key):
        """
        Sign each of the inputs with the private key. Inputs should all be sent to
        the same scriptPubkey so we should only need one key.
        """
        seckey = CBitcoinSecret.from_secret_bytes(unhexlify(priv_key))

        for i in range(len(self.outpoints)):
            txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(seckey.pub), OP_EQUALVERIFY, OP_CHECKSIG])
            sighash = SignatureHash(txin_scriptPubKey, self.tx, i, SIGHASH_ALL)
            sig = seckey.sign(sighash) + struct.pack('<B', SIGHASH_ALL)
            self.tx.vin[i].scriptSig = CScript([sig, seckey.pub])

            VerifyScript(self.tx.vin[0].scriptSig, txin_scriptPubKey, self.tx, 0, (SCRIPT_VERIFY_P2SH,))

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
