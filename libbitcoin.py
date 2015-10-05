__author__ = 'chris'
import obelisk
import struct
from obelisk import error_code
from binascii import  unhexlify
from twisted.internet import reactor

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
        'broadcast_transaction',
        'validate'
    ]

    # pylint: disable=R0201
    def _on_broadcast_transaction(self, data):
        def unpack_error(data):
            value = struct.unpack_from('<I', data, 0)[0]
            return error_code.error_code.name_from_id(value)
        return (unpack_error(data), data)

    # pylint: disable=R0201
    def _on_validate(self, data):
        def unpack_error(data):
            value = struct.unpack_from('<I', data, 0)[0]
            return error_code.error_code.name_from_id(value)
        return (unpack_error(data), data)

    def broadcast(self, tx, retries=0):
        """
        A transaction broadcast function. After getting the response for the
        broadcast we will query the mempool to make sure it broadcast
        correctly. If there was an error, we will retry in 10 seconds.
        """

        # TODO: save unconfirmed transactions to the database so we can retry broadcast at startup

        def on_broadcast(error, data):
            def parse_result(error, result):
                if error:
                    if retries < 10:
                        print "Broadcast failure. Trying again in 6 seconds."
                        reactor.callLater(6, self.broadcast, tx, retries+1)
                else:
                    print "Broadcast Complete"

            self.send_command("transaction_pool.validate", unhexlify(tx), cb=parse_result)
        self.send_command("protocol.broadcast_transaction", unhexlify(tx), cb=on_broadcast)
