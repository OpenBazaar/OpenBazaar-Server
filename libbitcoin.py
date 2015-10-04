__author__ = 'chris'
import obelisk
from binascii import  unhexlify
from twisted.internet import reactor
import bitcoin

class LibbitcoinClient(obelisk.ObeliskOfLightClient):
    """
    An extension of the Obelisk client to handle transaction broadcasts.
    """

    valid_messages = [
        'fetch_block_header',
        'fetch_history',
        'fetch_history2',
        'subscribe',
        'fetch_last_height',
        'fetch_transaction',
        'fetch_txpool_transaction',
        'fetch_spend',
        'fetch_transaction_index',
        'fetch_block_transaction_hashes',
        'fetch_block_height',
        'fetch_stealth',
        'total_connections',
        'update',
        'renew',
        'broadcast_transaction'
    ]

    # pylint: disable=R0201
    def _on_broadcast_transaction(self, data):
        return ("error code", data)

    def broadcast(self, tx):
        """
        A transaction broadcast function. After getting the response for the
        broadcast we will query the server for the tx to make sure it broadcast
        correctly. If there was an error, we will retry in 10 seconds.
        """

        # TODO: set max retries for the broadcast
        # TODO: save unconfirmed transactions to the database so we can retry broadcast at startup

        def on_broadcast(error, data):
            def parse_result(ec, result):
                if bitcoin.txhash(result) == bitcoin.txhash(tx):
                    print "Broadcast Complete"
                else:
                    print "Broadcast failure. Trying again in 10 seconds."
                    reactor.callLater(10, self.broadcast, tx)
            self.fetch_transaction(unhexlify(bitcoin.txhash(tx)), cb=parse_result)

        if tx is type(str):
            tx = unhexlify(tx)
        self.send_command("protocol.broadcast_transaction", tx, cb=on_broadcast)
