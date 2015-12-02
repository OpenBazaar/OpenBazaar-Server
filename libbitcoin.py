__author__ = 'chris'
import obelisk
import struct
from obelisk import error_code
from binascii import  unhexlify
from twisted.internet import reactor, protocol
from log import Logger

class LibbitcoinClient(obelisk.ObeliskOfLightClient):
    """
    An extension of the Obelisk client to handle transaction broadcasts.
    """

    connected = True

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

    def broadcast(self, tx, cb=None, retries=0):
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
                        reactor.callLater(6, self.broadcast, tx, cb, retries+1)
                    elif cb:
                        cb(False)
                else:
                    print "Broadcast Complete"
                    if cb:
                        cb(True)

            self.send_command("transaction_pool.validate", unhexlify(tx), cb=parse_result)
        self.send_command("protocol.broadcast_transaction", unhexlify(tx), cb=on_broadcast)

    def validate(self, tx, cb=None):
        def parse_result(error, result):
            if error:
                if cb:
                    cb(False)
            else:
                if cb:
                    cb(True)
        self.send_command("transaction_pool.validate", unhexlify(tx), cb=parse_result)


class HeartbeatProtocol(protocol.Protocol):
    """
    For listening on the libbitcoin server heartbeat port
    """
    def __init__(self, libbitcoin_client):
        self.libbitcoin_client = libbitcoin_client
        self.timeout = reactor.callLater(7, self.call_timeout)
        self.log = Logger(system=self)

    def call_timeout(self):
        self.log.critical("Libbitcoin server offline")
        self.libbitcoin_client.connected = False

    def dataReceived(self, data):
        self.log.debug("libbitcoin heartbeat")
        self.timeout.cancel()
        self.libbitcoin_client.connected = True
        self.transport.loseConnection()


class HeartbeatFactory(protocol.ClientFactory):
    def __init__(self, libbitcoin_client):
        self.libbitcoin_client = libbitcoin_client
        self.log = Logger(system=self)

    def buildProtocol(self, addr):
        self.protocol = HeartbeatProtocol(self.libbitcoin_client)
        return self.protocol

    def clientConnectionFailed(self, connector, reason):
        self.libbitcoin_client.connected = False
        self.log.critical("Libbitcoin server offline")
