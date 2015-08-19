__author__ = 'chris'
import sqlite3 as lite

from constants import DATABASE
from protos.objects import Listings, Followers, Following


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
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE hashmap(hash BLOB PRIMARY KEY, filepath TEXT)''')
            self.db.commit()
        except Exception:
            pass

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
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE profile(id INTEGER PRIMARY KEY, serializedUserInfo BLOB)''')
            self.db.commit()
        except Exception:
            pass

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
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE listings(id INTEGER PRIMARY KEY, serializedListings BLOB)''')
            self.db.commit()
        except Exception:
            pass

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
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE keystore(type TEXT PRIMARY KEY, privkey BLOB, pubkey BLOB)''')
            self.db.commit()
        except Exception:
            pass

    def set_key(self, key_type, privkey, pubkey):
        cursor = self.db.cursor()
        cursor.execute('''INSERT OR REPLACE INTO keystore(type, privkey, pubkey)
                      VALUES (?,?,?)''', (key_type, privkey, pubkey))
        self.db.commit()

    def get_key(self, key_type):
        cursor = self.db.cursor()
        cursor.execute('''SELECT privkey, pubkey FROM keystore WHERE type=?''', (key_type,))
        ret = cursor.fetchone()
        if not ret:
            return None
        else:
            return ret

    def delete_all_keys(self):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM keystore''')
        self.db.commit()


class FollowData(object):
    def __init__(self):
        self.db = lite.connect(DATABASE)
        self.db.text_factory = str
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE followers(id INTEGER PRIMARY KEY, serializedFollowers BLOB)''')
            cursor.execute('''CREATE TABLE following(id INTEGER PRIMARY KEY, serializedFollowing BLOB)''')
            self.db.commit()
        except Exception:
            pass

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
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE messages(guid BLOB , handle TEXT, signed_pubkey BLOB,
encryption_pubkey BLOB, subject TEXT, message_type TEXT, message TEXT, timestamp, INTEGER,
avatar_hash BLOB, signature BLOB)''')
            cursor.execute('''CREATE INDEX idx1 ON messages(guid);''')
            self.db.commit()
        except Exception:
            pass

    def save_message(self, guid, handle, signed_pubkey, encryption_pubkey,
                     subject, message_type, message, timestamp, avatar_hash, signature):
        cursor = self.db.cursor()
        cursor.execute('''INSERT INTO messages(guid, handle, signed_pubkey, encryption_pubkey, subject,
message_type, message, timestamp, avatar_hash, signature) VALUES (?,?,?,?,?,?,?,?,?,?)''',
                       (guid, handle, signed_pubkey, encryption_pubkey, subject, message_type,
                        message, timestamp, avatar_hash, signature))
        self.db.commit()

    def get_messages(self, guid, message_type):
        cursor = self.db.cursor()
        cursor.execute('''SELECT guid, handle, signed_pubkey, encryption_pubkey, subject, message_type, message,
timestamp, avatar_hash, signature FROM messages WHERE guid=? AND message_type=?''', (guid, message_type))
        ret = cursor.fetchall()
        if not ret:
            return None
        else:
            return ret

    def delete_message(self, guid):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM messages WHERE guid=? AND message_type="CHAT"''', (guid, ))
        self.db.commit()

class NotificationStore(object):
    def __init__(self):
        self.db = lite.connect(DATABASE)
        self.db.text_factory = str
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE notifications(guid BLOB, handle TEXT, message TEXT,
timestamp INTEGER, avatar_hash BLOB)''')
            self.db.commit()
        except Exception:
            pass

    def save_notification(self, guid, handle, message, timestamp, avatar_hash):
        cursor = self.db.cursor()
        cursor.execute('''INSERT INTO notifications(guid, handle, message, timestamp, avatar_hash)
VALUES (?,?,?,?,?)''', (guid, handle, message, timestamp, avatar_hash))
        self.db.commit()

    def get_notifications(self):
        cursor = self.db.cursor()
        cursor.execute('''SELECT guid, handle, message, timestamp, avatar_hash FROM notifications''')
        ret = cursor.fetchall()
        if not ret:
            return None
        else:
            return ret

    def delete_notfication(self, guid, timestamp):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM notifications WHERE guid=? AND timestamp=?''', (guid, timestamp))
        self.db.commit()
