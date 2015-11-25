__author__ = 'chris'
import sqlite3 as lite
import os
from constants import DATA_FOLDER
from protos.objects import Listings, Followers, Following
from dht.node import Node
from binascii import unhexlify
from collections import Counter


class Database(object):

    # pylint: disable=W0601
    DATABASE = None

    def __init__(self, testnet=False, filepath=None):
        global DATABASE
        self.TESTNET = testnet
        if testnet:
            DATABASE = DATA_FOLDER + "OB-Testnet.db"
        else:
            DATABASE = DATA_FOLDER + "OB-Mainnet.db"
        self.DATABASE = DATABASE
        if filepath:
            DATABASE = filepath
        if not os.path.exists(DATA_FOLDER + "cache/"):
            os.makedirs(DATA_FOLDER + "cache/")
        if not os.path.exists(DATA_FOLDER + "store/listings/contracts/"):
            os.makedirs(DATA_FOLDER + "store/listings/contracts/")
        if not os.path.exists(DATA_FOLDER + "store/listings/in progress/"):
            os.makedirs(DATA_FOLDER + "store/listings/in progress/")
        if not os.path.exists(DATA_FOLDER + "store/listings/trade receipts/"):
            os.makedirs(DATA_FOLDER + "store/listings/trade receipts/")
        if not os.path.exists(DATA_FOLDER + "store/media/"):
            os.makedirs(DATA_FOLDER + "store/media/")
        if not os.path.exists(DATA_FOLDER + "purchases/in progress/"):
            os.makedirs(DATA_FOLDER + "purchases/in progress/")
        if not os.path.exists(DATA_FOLDER + "purchases/trade receipts/"):
            os.makedirs(DATA_FOLDER + "purchases/trade receipts/")
        if not os.path.isfile(DATABASE):
            self.create_database()
            if os.path.exists(DATA_FOLDER + "cache.pickle"):
                os.remove(DATA_FOLDER + "cache.pickle")

    @staticmethod
    def create_database(filepath=None):
        if filepath is None:
            db = lite.connect(DATABASE)
        else:
            db = lite.connect(filepath)

        cursor = db.cursor()
        cursor.execute('''CREATE TABLE hashmap(hash TEXT PRIMARY KEY, filepath TEXT)''')

        cursor.execute('''CREATE TABLE profile(id INTEGER PRIMARY KEY, serializedUserInfo BLOB)''')

        cursor.execute('''CREATE TABLE listings(id INTEGER PRIMARY KEY, serializedListings BLOB)''')

        cursor.execute('''CREATE TABLE keys(type TEXT PRIMARY KEY, privkey BLOB, pubkey BLOB)''')

        cursor.execute('''CREATE TABLE followers(id INTEGER PRIMARY KEY, serializedFollowers BLOB)''')

        cursor.execute('''CREATE TABLE following(id INTEGER PRIMARY KEY, serializedFollowing BLOB)''')

        cursor.execute('''CREATE TABLE messages(guid TEXT, handle TEXT, signed_pubkey BLOB,
    encryption_pubkey BLOB, subject TEXT, message_type TEXT, message TEXT, timestamp INTEGER,
    avatar_hash BLOB, signature BLOB, outgoing INTEGER, read INTEGER)''')
        cursor.execute('''CREATE INDEX index_messages_guid ON messages(guid);''')
        cursor.execute('''CREATE INDEX index_messages_read ON messages(read);''')


        cursor.execute('''CREATE TABLE notifications(id TEXT PRIMARY KEY, guid BLOB, handle TEXT, type TEXT,
    order_id TEXT, title TEXT, timestamp INTEGER, image_hash BLOB, read INTEGER)''')

        cursor.execute('''CREATE TABLE broadcasts(id TEXT PRIMARY KEY, guid BLOB, handle TEXT, message TEXT,
    timestamp INTEGER, avatar_hash BLOB)''')

        cursor.execute('''CREATE TABLE vendors(guid TEXT PRIMARY KEY, ip TEXT, port INTEGER, signedPubkey BLOB)''')

        cursor.execute('''CREATE TABLE moderators(guid TEXT PRIMARY KEY, signedPubkey BLOB, encryptionKey BLOB,
    encryptionSignature BLOB, bitcoinKey BLOB, bitcoinSignature BLOB, handle TEXT, name TEXT, description TEXT,
    avatar BLOB, fee FLOAT)''')

        cursor.execute('''CREATE TABLE purchases(id TEXT PRIMARY KEY, title TEXT, timestamp INTEGER, btc FLOAT,
    address TEXT, status INTEGER, outpoint BLOB, thumbnail BLOB, seller TEXT, proofSig BLOB)''')

        cursor.execute('''CREATE TABLE sales(id TEXT PRIMARY KEY, title TEXT, timestamp INTEGER, btc REAL,
    address TEXT, status INTEGER, thumbnail BLOB, outpoint BLOB, seller TEXT, paymentTX TEXT)''')

        cursor.execute('''CREATE TABLE settings(id INTEGER PRIMARY KEY, refundAddress TEXT, currencyCode TEXT,
country TEXT, language TEXT, timeZone TEXT, notifications INTEGER, shippingAddresses BLOB, blocked BLOB,
libbitcoinServer TEXT, SSL INTEGER, seed TEXT, terms_conditions TEXT, refund_policy TEXT)''')

        db.commit()
        return db

    class HashMap(object):
        """
        Creates a table in the database for mapping file hashes (which are sent
        over the wire in a query) with a more human readable filename in local
        storage. This is useful for users who want to look through their store
        data on disk.
        """

        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def insert(self, hash_value, filepath):
            cursor = self.db.cursor()
            cursor.execute('''INSERT OR REPLACE INTO hashmap(hash, filepath)
                          VALUES (?,?)''', (hash_value, filepath))
            self.db.commit()

        def get_file(self, hash_value):
            cursor = self.db.cursor()
            cursor.execute('''SELECT filepath FROM hashmap WHERE hash=?''', (hash_value,))
            ret = cursor.fetchone()
            if ret is None:
                return None
            return ret[0]

        def get_all(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT * FROM hashmap ''')
            ret = cursor.fetchall()
            return ret

        def delete(self, hash_value):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM hashmap WHERE hash = ?''', (hash_value,))
            self.db.commit()

        def delete_all(self):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM hashmap''')
            self.db.commit()

    class ProfileStore(object):
        """
        Stores the user's profile data in the db. The profile is stored as a serialized
        Profile protobuf object. It's done this way because because protobuf is more
        flexible and allows for storing custom repeated fields (like the SocialAccount
        object). Also we will just serve this over the wire so we don't have to manually
        rebuild it every startup. To interact with the profile you should use the
        `market.profile` module and not this class directly.
        """

        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def set_proto(self, proto):
            cursor = self.db.cursor()
            cursor.execute('''INSERT OR REPLACE INTO profile(id, serializedUserInfo)
                          VALUES (?,?)''', (1, proto))
            self.db.commit()

        def get_proto(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT serializedUserInfo FROM profile WHERE id = 1''')
            ret = cursor.fetchone()
            if ret is None:
                return None
            return ret[0]

    class ListingsStore(object):
        """
        Stores a serialized `Listings` protobuf object. It contains metadata for all the
        contracts hosted by this store. We will send this in response to a GET_LISTING
        query. This should be updated each time a new contract is created.
        """

        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def add_listing(self, proto):
            """
            Will also update an existing listing if the contract hash is the same.
            """
            cursor = self.db.cursor()
            l = Listings()
            ser = self.get_proto()
            if ser is not None:
                l.ParseFromString(ser)
                for listing in l.listing:
                    if listing.contract_hash == proto.contract_hash:
                        l.listing.remove(listing)
            l.listing.extend([proto])
            cursor.execute('''INSERT OR REPLACE INTO listings(id, serializedListings)
                          VALUES (?,?)''', (1, l.SerializeToString()))
            self.db.commit()

        def delete_listing(self, hash_value):
            cursor = self.db.cursor()
            ser = self.get_proto()
            if ser is None:
                return
            l = Listings()
            l.ParseFromString(ser)
            for listing in l.listing:
                if listing.contract_hash == hash_value:
                    l.listing.remove(listing)
            cursor.execute('''INSERT OR REPLACE INTO listings(id, serializedListings)
                          VALUES (?,?)''', (1, l.SerializeToString()))
            self.db.commit()

        def delete_all_listings(self):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM listings''')
            self.db.commit()

        def get_proto(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT serializedListings FROM listings WHERE id = 1''')
            ret = cursor.fetchone()
            if ret is None:
                return None
            return ret[0]

    class KeyStore(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def set_key(self, key_type, privkey, pubkey):
            cursor = self.db.cursor()
            cursor.execute('''INSERT OR REPLACE INTO keys(type, privkey, pubkey)
                          VALUES (?,?,?)''', (key_type, privkey, pubkey))
            self.db.commit()

        def get_key(self, key_type):
            cursor = self.db.cursor()
            cursor.execute('''SELECT privkey, pubkey FROM keys WHERE type=?''', (key_type,))
            ret = cursor.fetchone()
            if not ret:
                return None
            else:
                return ret

        def delete_all_keys(self):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM keys''')
            self.db.commit()

    class FollowData(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def follow(self, proto):
            cursor = self.db.cursor()
            f = Following()
            ser = self.get_following()
            if ser is not None:
                f.ParseFromString(ser)
                for user in f.users:
                    if user.guid == proto.guid:
                        f.users.remove(user)
            f.users.extend([proto])
            cursor.execute('''INSERT OR REPLACE INTO following(id, serializedFollowing) VALUES (?,?)''',
                           (1, f.SerializeToString()))
            self.db.commit()

        def unfollow(self, guid):
            cursor = self.db.cursor()
            f = Following()
            ser = self.get_following()
            if ser is not None:
                f.ParseFromString(ser)
                for user in f.users:
                    if user.guid == guid:
                        f.users.remove(user)
            cursor.execute('''INSERT OR REPLACE INTO following(id, serializedFollowing) VALUES (?,?)''',
                           (1, f.SerializeToString()))
            self.db.commit()

        def get_following(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT serializedFollowing FROM following WHERE id=1''')
            ret = cursor.fetchall()
            if not ret:
                return None
            else:
                return ret[0][0]

        def is_following(self, guid):
            f = Following()
            ser = self.get_following()
            if ser is not None:
                f.ParseFromString(ser)
                for user in f.users:
                    if user.guid == guid:
                        return True
            return False

        def set_follower(self, proto):
            cursor = self.db.cursor()
            f = Followers()
            ser = self.get_followers()
            if ser is not None:
                f.ParseFromString(ser)
                for follower in f.followers:
                    if follower.guid == proto.guid:
                        f.followers.remove(follower)
            f.followers.extend([proto])
            cursor.execute('''INSERT OR REPLACE INTO followers(id, serializedFollowers) VALUES (?,?)''',
                           (1, f.SerializeToString()))
            self.db.commit()

        def delete_follower(self, guid):
            cursor = self.db.cursor()
            f = Followers()
            ser = self.get_followers()
            if ser is not None:
                f.ParseFromString(ser)
                for follower in f.followers:
                    if follower.guid == guid:
                        f.followers.remove(follower)
            cursor.execute('''INSERT OR REPLACE INTO followers(id, serializedFollowers) VALUES (?,?)''',
                           (1, f.SerializeToString()))
            self.db.commit()

        def get_followers(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT serializedFollowers FROM followers WHERE id=1''')
            proto = cursor.fetchone()
            if not proto:
                return None
            else:
                return proto[0]

    class MessageStore(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def save_message(self, guid, handle, signed_pubkey, encryption_pubkey, subject,
                         message_type, message, timestamp, avatar_hash, signature, is_outgoing):
            outgoing = 1 if is_outgoing else 0
            cursor = self.db.cursor()
            cursor.execute('''INSERT INTO messages(guid, handle, signed_pubkey, encryption_pubkey, subject,
    message_type, message, timestamp, avatar_hash, signature, outgoing, read) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (guid, handle, signed_pubkey, encryption_pubkey, subject, message_type,
                            message, timestamp, avatar_hash, signature, outgoing, 0))
            self.db.commit()

        def get_messages(self, guid, message_type):
            cursor = self.db.cursor()
            cursor.execute('''SELECT guid, handle, signed_pubkey, encryption_pubkey, subject, message_type, message,
    timestamp, avatar_hash, signature, outgoing, read FROM messages WHERE guid=? AND message_type=?''',
                           (guid, message_type))
            return cursor.fetchall()

        def get_conversations(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT DISTINCT guid FROM messages''',)
            guids = cursor.fetchall()
            ret = []
            unread = self.get_unread()
            for g in guids:
                cursor.execute('''SELECT avatar_hash FROM messages WHERE guid=? and message_type="CHAT"''', (g[0],))
                val = cursor.fetchone()
                if val is not None:
                    ret.append({"guid": g[0],
                                "avatar_hash": val[0],
                                "unread": 0 if g[0] not in unread else unread[g[0]]})
            return ret

        def get_unread(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT guid FROM messages WHERE read=0''',)
            ret = []
            guids = cursor.fetchall()
            for g in guids:
                ret.append(g[0])
            return Counter(ret)


        def mark_as_read(self, guid):
            cursor = self.db.cursor()
            cursor.execute('''UPDATE messages SET read=? WHERE guid=?;''', (1, guid))
            self.db.commit()

        def delete_message(self, guid):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM messages WHERE guid=? AND message_type="CHAT"''', (guid, ))
            self.db.commit()

    class NotificationStore(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def save_notification(self, notif_id, guid, handle, notif_type, order_id, title, timestamp, image_hash):
            cursor = self.db.cursor()
            cursor.execute('''INSERT INTO notifications(id, guid, handle, type, order_id, title, timestamp,
image_hash, read) VALUES (?,?,?,?,?,?,?,?,?)''', (notif_id, guid, handle, notif_type, order_id, title, timestamp,
                                                  image_hash, 0))
            self.db.commit()

        def get_notifications(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT id, guid, handle, type, order_id, title, timestamp, image_hash, read
FROM notifications''')
            return cursor.fetchall()

        def mark_as_read(self, notif_id):
            cursor = self.db.cursor()
            cursor.execute('''UPDATE notifications SET read=? WHERE id=?;''', (1, notif_id))
            self.db.commit()

        def delete_notification(self, notif_id):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM notifications WHERE id=?''', (notif_id,))
            self.db.commit()

    class BroadcastStore(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def save_broadcast(self, broadcast_id, guid, handle, message, timestamp, avatar_hash):
            cursor = self.db.cursor()
            cursor.execute('''INSERT INTO broadcasts(id, guid, handle, message, timestamp, avatar_hash)
    VALUES (?,?,?,?,?,?)''', (broadcast_id, guid, handle, message, timestamp, avatar_hash))
            self.db.commit()

        def get_broadcasts(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT id, guid, handle, message, timestamp, avatar_hash FROM broadcasts''')
            return cursor.fetchall()

        def delete_broadcast(self, broadcast_id):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM broadcasts WHERE id=?''', (broadcast_id,))
            self.db.commit()

    class VendorStore(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def save_vendor(self, guid, ip, port, signed_pubkey):
            cursor = self.db.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO vendors(guid, ip, port, signedPubkey)
    VALUES (?,?,?,?)''', (guid, ip, port, signed_pubkey))
            except Exception as e:
                print e.message
            self.db.commit()

        def get_vendors(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT guid, ip, port, signedPubkey FROM vendors''')
            ret = cursor.fetchall()
            nodes = []
            for n in ret:
                node = Node(unhexlify(n[0]), n[1], n[2], n[3], True)
                nodes.append(node)
            return nodes

        def delete_vendor(self, guid):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM vendors WHERE guid=?''', (guid,))
            self.db.commit()

    class ModeratorStore(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def save_moderator(self, guid, signed_pubkey, encryption_key, encription_sig,
                           bitcoin_key, bicoin_sig, name, avatar_hash, fee, handle="", short_desc=""):
            cursor = self.db.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO moderators(guid, signedPubkey, encryptionKey,
    encryptionSignature, bitcoinKey, bitcoinSignature, handle, name, description, avatar, fee)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)''', (guid, signed_pubkey, encryption_key, encription_sig, bitcoin_key,
                                        bicoin_sig, handle, name, short_desc, avatar_hash, fee))
            except Exception as e:
                print e.message
            self.db.commit()

        def get_moderator(self, guid):
            cursor = self.db.cursor()
            cursor.execute('''SELECT guid, signedPubkey, encryptionKey, encryptionSignature, bitcoinKey,
     bitcoinSignature, handle, name, description, avatar, fee FROM moderators WHERE guid=?''', (guid,))
            ret = cursor.fetchall()
            if not ret:
                return None
            else:
                return ret[0]

        def delete_moderator(self, guid):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM moderators WHERE guid=?''', (guid,))
            self.db.commit()

        def clear_all(self):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM moderators''')
            self.db.commit()

    class Purchases(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def new_purchase(self, order_id, title, timestamp, btc,
                         address, status, thumbnail, seller, proofSig):
            cursor = self.db.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO purchases(id, title, timestamp, btc, address, status,
    thumbnail, seller, proofSig) VALUES (?,?,?,?,?,?,?,?,?)''',
                               (order_id, title, timestamp, btc, address, status, thumbnail, seller, proofSig))
            except Exception as e:
                print e.message
            self.db.commit()

        def get_purchase(self, order_id):
            cursor = self.db.cursor()
            cursor.execute('''SELECT id, title, timestamp, btc, address, status,
     thumbnail, seller, proofSig FROM purchases WHERE id=?''', (order_id,))
            ret = cursor.fetchall()
            if not ret:
                return None
            else:
                return ret[0]

        def delete_purchase(self, order_id):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM purchases WHERE id=?''', (order_id,))
            self.db.commit()

        def get_all(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT id, title, timestamp, btc, address, status,
     thumbnail, seller, proofSig FROM purchases ''')
            ret = cursor.fetchall()
            if not ret:
                return None
            else:
                return ret

        def update_status(self, order_id, status):
            cursor = self.db.cursor()
            cursor.execute('''UPDATE purchases SET status=? WHERE id=?;''', (status, order_id))
            self.db.commit()

        def update_outpoint(self, order_id, outpoint):
            cursor = self.db.cursor()
            cursor.execute('''UPDATE purchases SET outpoint=? WHERE id=?;''', (outpoint, order_id))
            self.db.commit()

        def get_outpoint(self, order_id):
            cursor = self.db.cursor()
            cursor.execute('''SELECT outpoint FROM purchases WHERE id=?''', (order_id,))
            ret = cursor.fetchone()
            if not ret:
                return None
            else:
                return ret[0]

    class Sales(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def new_sale(self, order_id, title, timestamp, btc,
                     address, status, thumbnail, seller):
            cursor = self.db.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO sales(id, title, timestamp, btc, address, status,
    thumbnail, seller) VALUES (?,?,?,?,?,?,?,?)''',
                               (order_id, title, timestamp, btc, address, status, thumbnail, seller))
            except Exception as e:
                print e.message
            self.db.commit()

        def get_sale(self, order_id):
            cursor = self.db.cursor()
            cursor.execute('''SELECT id, title, timestamp, btc, address, status,
    thumbnail, seller FROM sales WHERE id=?''', (order_id,))
            ret = cursor.fetchall()
            if not ret:
                return None
            else:
                return ret[0]

        def delete_sale(self, order_id):
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM sales WHERE id=?''', (order_id,))
            self.db.commit()

        def get_all(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT id, title, timestamp, btc, address, status,
    thumbnail, seller, paymentTX FROM sales ''')
            ret = cursor.fetchall()
            if not ret:
                return None
            else:
                return ret

        def update_status(self, order_id, status):
            cursor = self.db.cursor()
            cursor.execute('''UPDATE sales SET status=? WHERE id=?;''', (status, order_id))
            self.db.commit()

        def update_outpoint(self, order_id, outpoint):
            cursor = self.db.cursor()
            cursor.execute('''UPDATE sales SET outpoint=? WHERE id=?;''', (outpoint, order_id))
            self.db.commit()

        def update_payment_tx(self, order_id, txid):
            cursor = self.db.cursor()
            cursor.execute('''UPDATE sales SET paymentTX=? WHERE id=?;''', (txid, order_id))
            self.db.commit()

        def get_outpoint(self, order_id):
            cursor = self.db.cursor()
            cursor.execute('''SELECT outpoint FROM sales WHERE id=?''', (order_id,))
            ret = cursor.fetchone()
            if not ret:
                return None
            else:
                return ret[0]

    class Settings(object):
        def __init__(self):
            self.db = lite.connect(DATABASE)
            self.db.text_factory = str

        def update(self, refundAddress, currencyCode, country, language, timeZone, notifications,
                   shipping_addresses, blocked, libbitcoinServer, ssl, seed, terms_conditions, refund_policy):
            cursor = self.db.cursor()
            cursor.execute('''INSERT OR REPLACE INTO settings(id, refundAddress, currencyCode, country,
language, timeZone, notifications, shippingAddresses, blocked, libbitcoinServer, ssl, seed,
terms_conditions, refund_policy) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (1, refundAddress, currencyCode, country, language, timeZone,
                            notifications, shipping_addresses, blocked,
                            libbitcoinServer, ssl, seed, terms_conditions,
                            refund_policy))
            self.db.commit()

        def get(self):
            cursor = self.db.cursor()
            cursor.execute('''SELECT * FROM settings WHERE id=1''')
            ret = cursor.fetchall()
            if not ret:
                return None
            else:
                return ret[0]
