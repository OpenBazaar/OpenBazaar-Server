__author__ = 'chris'
import struct
from binascii import  unhexlify
from twisted.internet import reactor, task
from obelisk import error_code
from obelisk import ObeliskOfLightClient
from obelisk.zmq_fallback import ZmqSocket
import zmq
from log import Logger


class LibbitcoinClient(ObeliskOfLightClient):
    """
    An extension of the Obelisk client to handle transaction broadcasts.
    """

    def __init__(self, address):
        ObeliskOfLightClient.__init__(self, address)
        self. address = address
        self.connected = False
        self.log = Logger(system="LibbitcoinClient")
        self.start_heartbeat()
        task.LoopingCall(self.refresh_connection).start(600)


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

    def refresh_connection(self):
        if self.subscribed == 0:
            self._socket.close()
            self._socket = self.setup(self.address)

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

    def broadcast(self, tx, cb=None):
        """
        A transaction broadcast function.
        """

        # TODO: save unconfirmed transactions to the database so we can retry broadcast at startup

        def on_broadcast(error, data):
            if error:
                self.log.critical("Transaction %s broadcast failed" % tx)
                cb(False)
            else:
                self.log.info("Transaction %s broadcast complete" % tx)
                cb(True)

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

    def start_heartbeat(self):

        def timeout():
            self.connected = False
            self.log.critical("Libbitcoin server offline")

        def frame_received(frame, more):
            t.reset(10)
            if not self.connected:
                self.connected = True
                self.log.info("Libbitcoin server online")

        t = reactor.callLater(10, timeout)

        s = ZmqSocket(frame_received, 3, type=zmq.SUB)
        s.connect(self.address[:len(self.address) - 4] + "9092")
