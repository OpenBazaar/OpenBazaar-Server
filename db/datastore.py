__author__ = 'chris'

import os
import sqlite3 as lite
import time
from api.utils import sanitize_html
from collections import Counter
from config import DATA_FOLDER
from dht.node import Node
from dht.utils import digest
from protos import objects
from protos.objects import Listings, Followers, Following
from os.path import join
from db.migrations import migration1, migration2, migration3, migration4, migration5, migration6, migration7


class Database(object):

    __slots__ = ['PATH', 'filemap', 'profile', 'listings', 'keys', 'follow', 'messages',
                 'notifications', 'broadcasts', 'vendors', 'moderators', 'purchases', 'sales',
                 'cases', 'ratings', 'transactions', 'settings', 'audit_shopping']

    def __init__(self, testnet=False, filepath=None):
        object.__setattr__(self, 'PATH', self._database_path(testnet, filepath))
        object.__setattr__(self, 'filemap', HashMap(self.PATH))
        object.__setattr__(self, 'profile', ProfileStore(self.PATH))
        object.__setattr__(self, 'listings', ListingsStore(self.PATH))
        object.__setattr__(self, 'keys', KeyStore(self.PATH))
        object.__setattr__(self, 'follow', FollowData(self.PATH))
        object.__setattr__(self, 'messages', MessageStore(self.PATH))
        object.__setattr__(self, 'notifications', NotificationStore(self.PATH))
        object.__setattr__(self, 'broadcasts', BroadcastStore(self.PATH))
        object.__setattr__(self, 'vendors', VendorStore(self.PATH))
        object.__setattr__(self, 'moderators', ModeratorStore(self.PATH))
        object.__setattr__(self, 'purchases', Purchases(self.PATH))
        object.__setattr__(self, 'sales', Sales(self.PATH))
        object.__setattr__(self, 'cases', Cases(self.PATH))
        object.__setattr__(self, 'ratings', Ratings(self.PATH))
        object.__setattr__(self, 'transactions', Transactions(self.PATH))
        object.__setattr__(self, 'settings', Settings(self.PATH))
        object.__setattr__(self, 'audit_shopping', ShoppingEvents(self.PATH))

        self._initialize_datafolder_tree()
        self._initialize_database(self.PATH)

    def get_database_path(self):
        return self.PATH

    def _initialize_database(self, database_path):
        """
        Create database, if not present, and clear cache.
        """
        if not database_path:
            raise RuntimeError('attempted to initialize empty path')

        if not os.path.isfile(database_path):
            self._create_database(database_path)
            cache = join(DATA_FOLDER, "cache.pickle")
            if os.path.exists(cache):
                os.remove(cache)

        self._run_migrations()

    @staticmethod
    def _database_path(testnet, filepath):
        '''
        Get database pathname.

        Args:
          testnet: Boolean
          filename: If provided, overrides testnet
        '''
        path = ''

        if filepath:
            path = filepath
        elif testnet:
            path = join(DATA_FOLDER, "OB-Testnet.db")
        else:
            path = join(DATA_FOLDER, "OB-Mainnet.db")

        return path

    @staticmethod
    def connect_database(path):
        conn = lite.connect(path)
        conn.text_factory = str
        return conn

    @staticmethod
    def _initialize_datafolder_tree():
        """
        Creates, if not present, directory tree in DATA_FOLDER.
        """
        tree = [
            ['cache'],
            ['store', 'contracts', 'listings'],
            ['store', 'contracts', 'in progress'],
            ['store', 'contracts', 'unfunded'],
            ['store', 'contracts', 'trade receipts'],
            ['store', 'media'],
            ['purchases', 'in progress'],
            ['purchases', 'unfunded'],
            ['purchases', 'trade receipts'],
            ['cases']
        ]

        path = ''
        for sub_tree in tree:
            path = DATA_FOLDER
            for directory in sub_tree:
                path = join(path, directory)
            if not os.path.exists(path):
                os.makedirs(path, mode=0o750)

    @staticmethod
    def _create_database(database_path):
        conn = lite.connect(database_path)
        cursor = conn.cursor()

        cursor.execute('''PRAGMA user_version = 6''')
        cursor.execute('''CREATE TABLE hashmap(hash TEXT PRIMARY KEY, filepath TEXT)''')

        cursor.execute('''CREATE TABLE profile(id INTEGER PRIMARY KEY, serializedUserInfo BLOB, tempHandle TEXT)''')

        cursor.execute('''CREATE TABLE listings(id INTEGER PRIMARY KEY, serializedListings BLOB)''')

        cursor.execute('''CREATE TABLE keys(type TEXT PRIMARY KEY, privkey BLOB, pubkey BLOB)''')

        cursor.execute('''CREATE TABLE followers(guid TEXT UNIQUE, serializedFollower TEXT)''')
        cursor.execute('''CREATE INDEX index_followers ON followers(serializedFollower);''')

        cursor.execute('''CREATE TABLE following(id INTEGER PRIMARY KEY, serializedFollowing BLOB)''')

        cursor.execute('''CREATE TABLE messages(msgID TEXT PRIMARY KEY, guid TEXT, handle TEXT, pubkey BLOB,
    subject TEXT, messageType TEXT, message TEXT, timestamp INTEGER, avatarHash BLOB, signature BLOB,
    outgoing INTEGER, read INTEGER)''')
        cursor.execute('''CREATE INDEX index_guid ON messages(guid);''')
        cursor.execute('''CREATE INDEX index_subject ON messages(subject);''')
        cursor.execute('''CREATE INDEX index_messages_read ON messages(read);''')
        cursor.execute('''CREATE INDEX index_timestamp ON messages(timestamp);''')

        cursor.execute('''CREATE TABLE notifications(notifID TEXT UNIQUE, guid BLOB, handle TEXT, type TEXT,
    orderId TEXT, title TEXT, timestamp INTEGER, imageHash BLOB, read INTEGER)''')
        cursor.execute('''CREATE INDEX index_notification_read ON notifications(read);''')

        cursor.execute('''CREATE TABLE broadcasts(id TEXT PRIMARY KEY, guid BLOB, handle TEXT, message TEXT,
    timestamp INTEGER, avatarHash BLOB)''')

        cursor.execute('''CREATE TABLE vendors(guid TEXT PRIMARY KEY, serializedNode BLOB)''')

        cursor.execute('''CREATE TABLE moderators(guid TEXT PRIMARY KEY, pubkey BLOB, bitcoinKey BLOB,
    bitcoinSignature BLOB, handle TEXT, name TEXT, description TEXT, avatar BLOB, fee FLOAT)''')

        cursor.execute('''CREATE TABLE purchases(id TEXT PRIMARY KEY, title TEXT, description TEXT,
    timestamp INTEGER, btc FLOAT, address TEXT, status INTEGER, outpoint BLOB, thumbnail BLOB, vendor TEXT,
    proofSig BLOB, contractType TEXT, unread INTEGER, statusChanged INTEGER)''')

        cursor.execute('''CREATE TABLE sales(id TEXT PRIMARY KEY, title TEXT, description TEXT,
    timestamp INTEGER, btc REAL, address TEXT, status INTEGER, thumbnail BLOB, outpoint BLOB, buyer TEXT,
    paymentTX TEXT, contractType TEXT, unread INTEGER, statusChanged INTEGER)''')

        cursor.execute('''CREATE TABLE cases(id TEXT PRIMARY KEY, title TEXT, timestamp INTEGER, orderDate TEXT,
    btc REAL, thumbnail BLOB, buyer TEXT, vendor TEXT, validation TEXT, claim TEXT, status INTEGER,
    unread INTEGER, statusChanged INTEGER)''')

        cursor.execute('''CREATE TABLE ratings(listing TEXT, ratingID TEXT,  rating TEXT)''')
        cursor.execute('''CREATE INDEX index_listing ON ratings(listing);''')
        cursor.execute('''CREATE INDEX index_rating_id ON ratings(ratingID);''')

        cursor.execute('''CREATE TABLE transactions(tx BLOB);''')

        cursor.execute('''CREATE TABLE settings(id INTEGER PRIMARY KEY, refundAddress TEXT, currencyCode TEXT,
    country TEXT, language TEXT, timeZone TEXT, notifications INTEGER, shippingAddresses BLOB, blocked BLOB,
    termsConditions TEXT, refundPolicy TEXT, moderatorList BLOB, username TEXT, password TEXT,
    smtpNotifications INTEGER, smtpServer TEXT, smtpSender TEXT, smtpRecipient TEXT, smtpUsername TEXT,
    smtpPassword TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS audit_shopping (
            audit_shopping_id integer PRIMARY KEY NOT NULL,
            shopper_guid text NOT NULL,
            contract_hash text NOT NULL,
            "timestamp" integer NOT NULL,
            action_id integer NOT NULL
          );''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS shopper_guid_index ON audit_shopping
                          (audit_shopping_id ASC);''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS action_id_index ON audit_shopping (audit_shopping_id ASC);''')

        conn.commit()
        conn.close()

    def _run_migrations(self):
        conn = self.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''PRAGMA user_version''')
        version = cursor.fetchone()[0]
        conn.close()

        if version == 0:
            migration1.migrate(self.PATH)
            migration2.migrate(self.PATH)
            migration3.migrate(self.PATH)
            migration4.migrate(self.PATH)
            migration5.migrate(self.PATH)
            migration6.migrate(self.PATH)
        elif version == 1:
            migration2.migrate(self.PATH)
            migration3.migrate(self.PATH)
            migration4.migrate(self.PATH)
            migration5.migrate(self.PATH)
            migration6.migrate(self.PATH)
        elif version == 2:
            migration3.migrate(self.PATH)
            migration4.migrate(self.PATH)
            migration5.migrate(self.PATH)
            migration6.migrate(self.PATH)
        elif version == 3:
            migration4.migrate(self.PATH)
            migration5.migrate(self.PATH)
            migration6.migrate(self.PATH)
        elif version == 4:
            migration5.migrate(self.PATH)
            migration6.migrate(self.PATH)
        elif version == 5:
            migration6.migrate(self.PATH)
            migration7.migrate(self.PATH)
        elif version == 6:
            migration7.migrate(self.PATH)


class HashMap(object):
    """
    Creates a table in the database for mapping file hashes (which are sent
    over the wire in a query) with a more human readable filename in local
    storage. This is useful for users who want to look through their store
    data on disk.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def insert(self, hash_value, filepath):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO hashmap(hash, filepath)
                          VALUES (?,?)''', (hash_value, filepath))
            conn.commit()
        conn.close()

    def get_file(self, hash_value):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT filepath FROM hashmap WHERE hash=?''', (hash_value,))
        ret = cursor.fetchone()
        conn.close()
        if ret is None:
            return None
        return DATA_FOLDER + ret[0]

    def get_all(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM hashmap ''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def delete(self, hash_value):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM hashmap WHERE hash = ?''', (hash_value,))
            conn.commit()
        conn.close()

    def delete_all(self):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM hashmap''')
            conn.commit()
        conn.close()


class ProfileStore(object):
    """
    Stores the user's profile data in the db. The profile is stored as a serialized
    Profile protobuf object. It's done this way because because protobuf is more
    flexible and allows for storing custom repeated fields (like the SocialAccount
    object). Also we will just serve this over the wire so we don't have to manually
    rebuild it every startup. To interact with the profile you should use the
    `market.profile` module and not this class directly.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def set_proto(self, proto):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            handle = self.get_temp_handle()
            cursor.execute('''INSERT OR REPLACE INTO profile(id, serializedUserInfo, tempHandle)
                          VALUES (?,?,?)''', (1, proto, handle))
            conn.commit()
        conn.close()

    def get_proto(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT serializedUserInfo FROM profile WHERE id = 1''')
        ret = cursor.fetchone()
        conn.close()
        if ret is None:
            return None
        return ret[0]

    def set_temp_handle(self, handle):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            if self.get_proto() is None:
                cursor.execute('''INSERT OR REPLACE INTO profile(id, tempHandle)
                          VALUES (?,?)''', (1, handle))
            else:
                cursor.execute('''UPDATE profile SET tempHandle=? WHERE id=?;''', (handle, 1))
            conn.commit()
        conn.close()

    def get_temp_handle(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT tempHandle FROM profile WHERE id = 1''')
        ret = cursor.fetchone()
        conn.close()
        if ret is None:
            return ""
        else:
            return ret[0]


class ListingsStore(object):
    """
    Stores a serialized `Listings` protobuf object. It contains metadata for all the
    contracts hosted by this store. We will send this in response to a GET_LISTING
    query. This should be updated each time a new contract is created.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def add_listing(self, proto):
        """
        Will also update an existing listing if the contract hash is the same.
        """
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
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
            conn.commit()
        conn.close()

    def delete_listing(self, hash_value):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
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
            conn.commit()
        conn.close()

    def delete_all_listings(self):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM listings''')
            conn.commit()
        conn.close()

    def get_proto(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT serializedListings FROM listings WHERE id = 1''')
        ret = cursor.fetchone()
        conn.close()
        if ret is None:
            return None
        return ret[0]


class KeyStore(object):
    """
    Stores the keys for this node.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def set_key(self, key_type, privkey, pubkey):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO keys(type, privkey, pubkey)
                          VALUES (?,?,?)''', (key_type, privkey, pubkey))
            conn.commit()
        conn.close()

    def get_key(self, key_type):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT privkey, pubkey FROM keys WHERE type=?''', (key_type,))
        ret = cursor.fetchone()
        conn.close()
        if not ret:
            return None
        else:
            return ret

    def delete_all_keys(self):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM keys''')
            conn.commit()
        conn.close()


class FollowData(object):
    """
    A class for saving and retrieving follower and following data
    for this node.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def follow(self, proto):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
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
            conn.commit()
        conn.close()

    def unfollow(self, guid):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            f = Following()
            ser = self.get_following()
            if ser is not None:
                f.ParseFromString(ser)
                for user in f.users:
                    if user.guid == guid:
                        f.users.remove(user)
            cursor.execute('''INSERT OR REPLACE INTO following(id, serializedFollowing) VALUES (?,?)''',
                           (1, f.SerializeToString()))
            conn.commit()
        conn.close()

    def get_following(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT serializedFollowing FROM following WHERE id=1''')
        ret = cursor.fetchall()
        conn.close()
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
        conn = Database.connect_database(self.PATH)
        p = Followers.Follower()
        p.ParseFromString(proto)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO followers(guid, serializedFollower) VALUES (?,?)''',
                           (p.guid.encode("hex"), proto.encode("hex")))
            conn.commit()
        conn.close()

    def delete_follower(self, guid):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM followers WHERE guid=?''', (guid.encode("hex"), ))
            conn.commit()
        conn.close()

    def get_followers(self, start=0):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()

        cursor.execute('''SELECT Count(*) FROM followers''')
        count = cursor.fetchone()[0]

        f = Followers()
        if count > 0:
            smt = '''select serializedFollower from followers order by rowid desc limit 30 offset ''' + str(start)
            cursor.execute(smt)
            serialized_followers = cursor.fetchall()
            conn.close()
            for proto in serialized_followers:
                p = Followers.Follower()
                p.ParseFromString(proto[0].decode("hex"))
                f.followers.extend([p])
        return (f.SerializeToString(), count)


class MessageStore(object):
    """
    Stores all of the chat messages for this node and allows retrieval of
    messages and conversations as well as marking as read.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def save_message(self, guid, handle, pubkey, subject, message_type, message,
                     timestamp, avatar_hash, signature, is_outgoing, msg_id=None):
        """
        Store message in database.
        """
        try:
            conn = Database.connect_database(self.PATH)
            with conn:
                outgoing = 1 if is_outgoing else 0
                msgID = digest(message + str(timestamp)).encode("hex") if msg_id is None else msg_id
                cursor = conn.cursor()
                cursor.execute('''INSERT INTO messages(msgID, guid, handle, pubkey, subject,
        messageType, message, timestamp, avatarHash, signature, outgoing, read) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                               (msgID, guid, handle, pubkey, subject, message_type,
                                message, timestamp, avatar_hash, signature, outgoing, 0))
                conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def get_messages(self, guid, message_type, msgID=None, limit=20):
        """
        Return all messages matching guid and message_type.
        """
        if msgID == None:
            timestamp = 4294967295
        else:
            timestamp = self.get_timestamp(msgID)
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT guid, handle, pubkey, subject, messageType, message,
timestamp, avatarHash, signature, outgoing, read, msgID FROM messages
WHERE guid=? AND messageType=? AND timestamp<? ORDER BY timestamp DESC LIMIT 20''', (guid, message_type, timestamp))
        ret = cursor.fetchall()
        conn.close()
        return ret

    def get_order_messages(self, order_id):
        """
        Return all messages matching guid and message_type.
        """
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT guid, handle, pubkey, subject, messageType, message, timestamp,
avatarHash, signature, outgoing, read FROM messages WHERE subject=? ''',
                       (order_id, ))
        ret = cursor.fetchall()
        conn.close()
        return ret

    def get_conversations(self):
        """
        Get all 'conversations' composed of messages of type 'CHAT'.

        Returns:
          Array of dictionaries, one element for each guid. Dictionaries
          include last message only.
        """
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT DISTINCT guid FROM messages''',)
        guids = cursor.fetchall()
        ret = []
        unread = self.get_unread()
        for g in guids:
            cursor.execute('''SELECT avatarHash, message, max(timestamp), pubkey FROM messages
WHERE guid=? and messageType=?''', (g[0], "CHAT"))
            val = cursor.fetchone()
            avatar_hash = None
            handle = ""
            if val[0] is not None:
                try:
                    with open(join(DATA_FOLDER, 'cache', g[0] + ".profile"), "r") as filename:
                        profile = filename.read()
                    p = objects.Profile()
                    p.ParseFromString(profile)
                    avatar_hash = p.avatar_hash.encode("hex")
                    handle = p.handle
                except Exception:
                    cursor.execute('''SELECT avatarHash FROM messages
WHERE guid=? and messageType=? and avatarHash NOT NULL''', (g[0], "CHAT"))
                    avi = cursor.fetchone()
                    if avi[0] is not None:
                        avatar_hash = avi[0].encode("hex")

                ret.append({"guid": g[0],
                            "avatar_hash": avatar_hash,
                            "handle": handle,
                            "last_message": val[1],
                            "timestamp": val[2],
                            "public_key": val[3].encode("hex"),
                            "unread": 0 if g[0] not in unread else unread[g[0]]})
        conn.close()
        return sanitize_html(ret)

    def get_unread(self):
        """
        Get Counter of guids which have unread, incoming messages.
        """
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT guid FROM messages WHERE read=0 and outgoing=0 and subject=""''',)
        ret = []
        guids = cursor.fetchall()
        for g in guids:
            ret.append(g[0])
        conn.close()
        return Counter(ret)

    def get_timestamp(self, msgID):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT timestamp FROM messages WHERE msgID=? and messageType=?''', (msgID, "CHAT"))
        ts = cursor.fetchone()[0]
        if ts is None:
            ts = 0
        conn.close()
        return ts

    def mark_as_read(self, guid):
        """
        Mark all messages for guid as read.
        """
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE messages SET read=? WHERE guid=?;''', (1, guid))
            conn.commit()
        conn.close()

    def delete_messages(self, guid):
        """
        Delete all messages of type 'CHAT' for guid.
        """
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM messages WHERE guid=? AND messageType="CHAT"''', (guid, ))
        conn.commit()
        conn.close()


class NotificationStore(object):
    """
    All notifications are stored here.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def save_notification(self, notif_id, guid, handle, notif_type, order_id, title, timestamp, image_hash):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO notifications(notifID, guid, handle, type, orderId, title, timestamp,
imageHash, read) VALUES (?,?,?,?,?,?,?,?,?)''', (notif_id, guid, handle, notif_type, order_id, title, timestamp,
                                                 image_hash, 0))
            conn.commit()
        conn.close()

    def get_notifications(self, notif_id, limit):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        start = self.get_row(notif_id)
        cursor.execute('''SELECT notifID, guid, handle, type, orderId, title, timestamp,
imageHash, read FROM notifications WHERE rowid <=? AND rowid > ?''', (start, start-limit))
        ret = cursor.fetchall()
        conn.close()
        return ret

    def get_row(self, notif_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT MAX(rowid) FROM notifications''')
        max_row = cursor.fetchone()[0]
        if max_row is None:
            max_row = 0
        cursor.execute('''SELECT rowid FROM notifications WHERE notifID=?''', (notif_id, ))
        ret = cursor.fetchone()
        conn.close()
        return max_row if not ret else ret[0]

    def mark_as_read(self, notif_id):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE notifications SET read=? WHERE notifID=?;''', (1, notif_id))
            conn.commit()
        conn.close()

    def get_unread_count(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT notifID FROM notifications WHERE read=?''', (0, ))
        ret = cursor.fetchall()
        conn.close()
        return len(ret)

    def delete_notification(self, notif_id):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM notifications WHERE notifID=?''', (notif_id,))
            conn.commit()
        conn.close()


class BroadcastStore(object):
    """
    Stores broadcast messages that our node receives.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def save_broadcast(self, broadcast_id, guid, handle, message, timestamp, avatar_hash):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO broadcasts(id, guid, handle, message, timestamp, avatarHash)
    VALUES (?,?,?,?,?,?)''', (broadcast_id, guid, handle, message, timestamp, avatar_hash))
            conn.commit()
        conn.close()

    def get_broadcasts(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, guid, handle, message, timestamp, avatarHash FROM broadcasts''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def delete_broadcast(self, broadcast_id):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM broadcasts WHERE id=?''', (broadcast_id,))
            conn.commit()
        conn.close()


class VendorStore(object):
    """
    Stores a list of vendors this node has heard about. Useful for
    filling out data in the homepage.
    """
    def __init__(self, database_path):
        self.PATH = database_path

    def save_vendor(self, guid, serialized_node):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO vendors(guid, serializedNode)
    VALUES (?,?)''', (guid, serialized_node))
            except Exception as e:
                print e.message
            conn.commit()
        conn.close()

    def get_vendors(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT serializedNode FROM vendors''')
        ret = cursor.fetchall()
        nodes = {}
        for n in ret:
            try:
                proto = objects.Node()
                proto.ParseFromString(n[0])
                node = Node(proto.guid,
                            proto.nodeAddress.ip,
                            proto.nodeAddress.port,
                            proto.publicKey,
                            None if not proto.HasField("relayAddress") else
                            (proto.relayAddress.ip, proto.relayAddress.port),
                            proto.natType,
                            proto.vendor)
                nodes[node.id] = node
            except Exception, e:
                print e.message
        conn.close()
        return nodes

    def delete_vendor(self, guid):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM vendors WHERE guid=?''', (guid,))
            conn.commit()
        conn.close()


class ModeratorStore(object):
    """
    Stores a list of known moderators. A moderator must be saved here
    for it to be used in a new listing.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def save_moderator(self, guid, pubkey, bitcoin_key, bicoin_sig, name,
                       avatar_hash, fee, handle="", short_desc=""):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO moderators(guid, pubkey, bitcoinKey,
bitcoinSignature, handle, name, description, avatar, fee)
    VALUES (?,?,?,?,?,?,?,?,?)''', (guid, pubkey, bitcoin_key, bicoin_sig, handle,
                                    name, short_desc, avatar_hash, fee))
            except Exception as e:
                print e.message
            conn.commit()
        conn.close()

    def get_moderator(self, guid):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM moderators WHERE guid=?''', (guid,))
        ret = cursor.fetchone()
        conn.close()
        return ret

    def delete_moderator(self, guid):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM moderators WHERE guid=?''', (guid,))
            conn.commit()
        conn.close()

    def clear_all(self, except_guids=None):
        if except_guids is None:
            except_guids = []
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM moderators WHERE guid NOT IN ({seq})'''.format(
                seq=','.join(['?']*len(except_guids))), except_guids)
            conn.commit()

        conn.close()


class Purchases(object):
    """
    Stores a list of this node's purchases.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def new_purchase(self, order_id, title, description, timestamp, btc,
                     address, status, thumbnail, vendor, proofSig, contract_type):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO purchases(id, title, description, timestamp, btc,
address, status, thumbnail, vendor, proofSig, contractType, unread) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                               (order_id, title, description, timestamp, btc, address,
                                status, thumbnail, vendor, proofSig, contract_type, 0))
            except Exception as e:
                print e.message
            conn.commit()
        conn.close()

    def get_purchase(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, title, description, timestamp, btc, address, status,
 thumbnail, vendor, contractType, proofSig, unread FROM purchases WHERE id=?''', (order_id,))
        ret = cursor.fetchall()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]

    def delete_purchase(self, order_id):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM purchases WHERE id=?''', (order_id,))
            conn.commit()
        conn.close()

    def get_all(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, title, description, timestamp, btc, status,
 thumbnail, vendor, contractType, unread, statusChanged FROM purchases ''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def get_unfunded(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, timestamp FROM purchases WHERE status=0 OR status=2''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def update_status(self, order_id, status):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE purchases SET status=? WHERE id=?;''', (status, order_id))
            conn.commit()
        conn.close()

    def status_changed(self, order_id, status):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE purchases SET statusChanged=? WHERE id=?;''', (status, order_id))
            conn.commit()
        conn.close()

    def get_status(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT status FROM purchases WHERE id=?''', (order_id,))
        ret = cursor.fetchone()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]

    def update_unread(self, order_id, reset=False):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            if reset is False:
                cursor.execute('''UPDATE purchases SET unread = unread + 1 WHERE id=?;''', (order_id,))
            else:
                cursor.execute('''UPDATE purchases SET unread=0 WHERE id=?;''', (order_id,))
            conn.commit()
        conn.close()

    def update_outpoint(self, order_id, outpoint):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE purchases SET outpoint=? WHERE id=?;''', (outpoint, order_id))
            conn.commit()
        conn.close()

    def get_outpoint(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT outpoint FROM purchases WHERE id=?''', (order_id,))
        ret = cursor.fetchone()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]

    def get_proof_sig(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT proofSig FROM purchases WHERE id=?''', (order_id,))
        ret = cursor.fetchone()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]


class Sales(object):
    """
    Stores a list of this node's sales.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def new_sale(self, order_id, title, description, timestamp, btc,
                 address, status, thumbnail, buyer, contract_type):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO sales(id, title, description, timestamp, btc, address,
status, thumbnail, buyer, contractType, unread) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                               (order_id, title, description, timestamp, btc, address, status,
                                thumbnail, buyer, contract_type, 0))
            except Exception as e:
                print e.message
            conn.commit()
        conn.close()

    def get_sale(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, title, description, timestamp, btc, address, status,
thumbnail, buyer, contractType, unread FROM sales WHERE id=?''', (order_id,))
        ret = cursor.fetchall()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]

    def delete_sale(self, order_id):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM sales WHERE id=?''', (order_id,))
            conn.commit()
        conn.close()

    def get_all(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, title, description, timestamp, btc, status,
thumbnail, buyer, contractType, unread, statusChanged FROM sales ''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def get_by_status(self, status):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, title, description, timestamp, btc, status,
thumbnail, buyer, contractType, unread, statusChanged FROM sales WHERE
status=?''', (status,))
        ret = cursor.fetchall()
        conn.close()
        return ret

    def get_unfunded(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, timestamp FROM sales WHERE status=0''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def update_status(self, order_id, status):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE sales SET status=? WHERE id=?;''', (status, order_id))
            conn.commit()
        conn.close()

    def status_changed(self, order_id, status):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE sales SET statusChanged=? WHERE id=?;''', (status, order_id))
            conn.commit()
        conn.close()

    def get_status(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT status FROM sales WHERE id=?''', (order_id,))
        ret = cursor.fetchone()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]

    def update_unread(self, order_id, reset=False):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            if reset is False:
                cursor.execute('''UPDATE sales SET unread = unread + 1 WHERE id=?;''', (order_id,))
            else:
                cursor.execute('''UPDATE sales SET unread=0 WHERE id=?;''', (order_id,))
            conn.commit()
        conn.close()

    def update_outpoint(self, order_id, outpoint):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE sales SET outpoint=? WHERE id=?;''', (outpoint, order_id))
            conn.commit()
        conn.close()

    def update_payment_tx(self, order_id, txid):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE sales SET paymentTX=? WHERE id=?;''', (txid, order_id))
            conn.commit()
        conn.close()

    def get_outpoint(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT outpoint FROM sales WHERE id=?''', (order_id,))
        ret = cursor.fetchone()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]


class Cases(object):
    """
    Stores a list of this node's moderation cases.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def new_case(self, order_id, title, timestamp, order_date, btc,
                 thumbnail, buyer, vendor, validation, claim):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''INSERT OR REPLACE INTO cases(id, title, timestamp, orderDate, btc, thumbnail,
buyer, vendor, validation, claim, status, unread) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                               (order_id, title, timestamp, order_date, btc,
                                thumbnail, buyer, vendor, validation, claim, 0, 0))
            except Exception as e:
                print e.message
            conn.commit()
        conn.close()

    def delete_case(self, order_id):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM cases WHERE id=?''', (order_id,))
            conn.commit()
        conn.close()

    def get_all(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT id, title, timestamp, orderDate, btc, thumbnail,
buyer, vendor, validation, claim, status, unread, statusChanged FROM cases ''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def update_unread(self, order_id, reset=False):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            if reset is False:
                cursor.execute('''UPDATE cases SET unread = unread + 1 WHERE id=?;''', (order_id,))
            else:
                cursor.execute('''UPDATE cases SET unread=0 WHERE id=?;''', (order_id,))
            conn.commit()
        conn.close()

    def get_claim(self, order_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT claim FROM cases WHERE id=?''', (order_id,))
        ret = cursor.fetchone()
        conn.close()
        if not ret:
            return None
        else:
            return ret[0]

    def update_status(self, order_id, status):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE cases SET status=? WHERE id=?;''', (status, order_id))
            conn.commit()
        conn.close()

    def status_changed(self, order_id, status):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE cases SET statusChanged=? WHERE id=?;''', (status, order_id))
            conn.commit()
        conn.close()


class Ratings(object):
    """
    Store ratings for each contract in the db.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def add_rating(self, listing_hash, rating):
        conn = Database.connect_database(self.PATH)
        with conn:
            rating_id = digest(rating).encode("hex")
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO ratings(listing, ratingID, rating) VALUES (?,?,?)''',
                           (listing_hash, rating_id, rating))
            conn.commit()
        conn.close()

    def get_listing_ratings(self, listing_hash, starting_id=None):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        if starting_id is None:
            cursor.execute('''SELECT rating FROM ratings WHERE listing=?''', (listing_hash,))
            ret = cursor.fetchall()
            conn.close()
            return ret
        else:
            cursor.execute('''SELECT rowid FROM ratings WHERE ratingID=?''', (starting_id, ))
            row_id = cursor.fetchone()
            if row_id is None:
                conn.close()
                return None
            else:
                cursor.execute('''SELECT rating FROM ratings WHERE rowid>? AND listing=?''',
                               (row_id, listing_hash))
                ret = cursor.fetchall()
                conn.close()
                return ret

    def get_all_ratings(self, starting_id=None):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        if starting_id is None:
            cursor.execute('''SELECT rating FROM ratings''')
            ret = cursor.fetchall()
            conn.close()
            return ret
        else:
            cursor.execute('''SELECT rowid FROM ratings WHERE ratingID=?''', (starting_id, ))
            row_id = cursor.fetchone()
            if row_id is None:
                conn.close()
                return None
            else:
                cursor.execute('''SELECT rating FROM ratings WHERE rowid>?''', (row_id, ))
                ret = cursor.fetchall()
                conn.close()
                return ret


class Transactions(object):
    """
    Store transactions that we broadcast to the network but have yet to confirm.
    The transactions should be periodically rebroadcast to ensure they make it in the chain.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def add_transaction(self, tx):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO transactions(tx) VALUES (?)''', (tx,))
            conn.commit()
        conn.close()

    def delete_transaction(self, tx):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM transactions WHERE tx=?''', (tx,))
            conn.commit()
        conn.close()

    def get_transactions(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT tx FROM transactions''')
        ret = cursor.fetchall()
        conn.close()
        return ret


class Settings(object):
    """
    Stores the UI settings.
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def update(self, refundAddress, currencyCode, country, language, timeZone, notifications,
               shipping_addresses, blocked, terms_conditions, refund_policy, moderator_list, smtp_notifications,
               smtp_server, smtp_sender, smtp_recipient, smtp_username, smtp_password):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO settings(id, refundAddress, currencyCode, country,
language, timeZone, notifications, shippingAddresses, blocked, termsConditions,
refundPolicy, moderatorList, smtpNotifications, smtpServer, smtpSender,
smtpRecipient, smtpUsername, smtpPassword) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (1, refundAddress, currencyCode, country, language, timeZone,
                            notifications, shipping_addresses, blocked, terms_conditions,
                            refund_policy, moderator_list, smtp_notifications, smtp_server,
                            smtp_sender, smtp_recipient, smtp_username, smtp_password))
            conn.commit()
        conn.close()

    def get(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM settings WHERE id=1''')
        ret = cursor.fetchone()
        conn.close()
        return ret

    def set_credentials(self, username, password):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO settings(id, username, password) VALUES (?,?,?)''',
                           (2, username, password))
            conn.commit()
        conn.close()

    def get_credentials(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT username, password FROM settings WHERE id=2''')
        ret = cursor.fetchone()
        conn.close()
        return ret

class ShoppingEvents(object):
    """
    Stores audit events for shoppers on your storefront
    """

    def __init__(self, database_path):
        self.PATH = database_path

    def set(self, shopper_guid, action_id, contract_hash=None):
        conn = Database.connect_database(self.PATH)
        with conn:
            cursor = conn.cursor()
            timestamp = int(time.time())
            if not contract_hash:
                contract_hash = ''
            cursor.execute('''INSERT INTO audit_shopping(shopper_guid, timestamp, contract_hash, action_id) VALUES
                              (?,?,?,?)''', (shopper_guid, timestamp, contract_hash, action_id))
            conn.commit()
        conn.close()

    def get(self):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM audit_shopping''')
        ret = cursor.fetchall()
        conn.close()
        return ret

    def get_events_by_id(self, event_id):
        conn = Database.connect_database(self.PATH)
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM audit_shopping WHERE event_id=?''', event_id)
        ret = cursor.fetchall()
        conn.close()
        return ret
