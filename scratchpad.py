__author__ = 'chris'
from libbitcoin import LibbitcoinClient
from twisted.internet import reactor

libbitcoin_client = LibbitcoinClient("tcp://libbitcoin2.openbazaar.org:9091")

def on_tx_received(address_version, address_hash, height, block_hash, tx):
    print tx
libbitcoin_client.subscribe_address(str("2MtLQgVyv7mFZpryjWpjg2BBKbgCJM8eVRp"), notification_cb=on_tx_received)

reactor.run()