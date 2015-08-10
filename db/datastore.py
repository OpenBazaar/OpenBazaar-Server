__author__ = 'chris'
import sqlite3 as lite
from constants import DATABASE
from protos.objects import Listings, Followers


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
            cursor.execute('''CREATE TABLE hashmap(hash BLOB primary key, filepath TEXT)''')
            self.db.commit()
        except:
            pass

    def insert(self, hash, filepath):
        cursor = self.db.cursor()
        cursor.execute('''INSERT OR REPLACE INTO hashmap(hash, filepath)
                      VALUES (?,?)''', (hash, filepath))
        self.db.commit()

    def get_file(self, hash):
        cursor = self.db.cursor()
        cursor.execute('''SELECT filepath FROM hashmap WHERE hash=?''', (hash,))
        ret = cursor.fetchone()
        if ret is None:
            return None
        return ret[0]

    def get_all(self):
        cursor = self.db.cursor()
        cursor.execute('''SELECT * FROM hashmap ''')
        ret = cursor.fetchall()
        return ret

    def delete(self, hash):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM hashmap WHERE hash = ?''', (hash,))
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
            cursor.execute('''CREATE TABLE profile(id INTEGER primary key, serializedUserInfo BLOB)''')
            self.db.commit()
        except:
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
            cursor.execute('''CREATE TABLE listings(id INTEGER primary key, serializedListings BLOB)''')
            self.db.commit()
        except:
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

    def delete_listing(self, hash):
        cursor = self.db.cursor()
        ser = self.get_proto()
        if ser is None:
            return
        l = Listings()
        l.ParseFromString(ser)
        for listing in l.listing:
            if listing.contract_hash == hash:
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
            return ret
        return ret[0]


class KeyStore(object):
    def __init__(self):
        self.db = lite.connect(DATABASE)
        self.db.text_factory = str
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE keystore(type TEXT primary key, privkey BLOB, pubkey BLOB)''')
            self.db.commit()
        except:
            pass

    def set_key(self, type, privkey, pubkey):
        cursor = self.db.cursor()
        cursor.execute('''INSERT OR REPLACE INTO keystore(type, privkey, pubkey)
                      VALUES (?,?,?)''', (type, privkey, pubkey))
        self.db.commit()

    def get_key(self, type):
        cursor = self.db.cursor()
        cursor.execute('''SELECT privkey, pubkey FROM keystore WHERE type=?''', (type,))
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
            cursor.execute('''CREATE TABLE followers(id INTEGER primary key, serializedFollowers BLOB)''')
            cursor.execute('''CREATE TABLE following(guid BLOB primary key)''')
            self.db.commit()
        except:
            pass

    def follow(self, guid):
        cursor = self.db.cursor()
        cursor.execute('''INSERT OR REPLACE INTO following(guid) VALUES (?)''', (guid,))
        self.db.commit()

    def unfollow(self, guid):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM following WHERE guid = ?''', (guid,))
        self.db.commit()

    def get_following(self):
        cursor = self.db.cursor()
        cursor.execute('''SELECT guid FROM following''')
        guids = cursor.fetchall()
        if not guids:
            return None
        else:
            ret = []
            for g in guids:
                ret.append(g[0])
            return ret

    def is_following(self, guid):
        cursor = self.db.cursor()
        cursor.execute('''SELECT guid FROM following WHERE guid = ?''', (guid,))
        guids = cursor.fetchone()
        if not guids:
            return False
        else:
            return True

    def set_follower(self, proto):
        cursor = self.db.cursor()
        f = Followers()
        ser = self.get_followers()
        if ser is not None:
            f.ParseFromString(ser)
            for follower in f.followers:
                if follower.follower_guid == proto.follower_guid:
                    f.follower.remove(follower)
        f.follower.extend([proto])
        cursor.execute('''INSERT OR REPLACE INTO followers(id, serializedFollowers) VALUES (?,?)''', (1, f.SerializeToString()))
        self.db.commit()

    def delete_follower(self, guid):
        cursor = self.db.cursor()
        f = Followers()
        ser = self.get_followers()
        if ser is not None:
            f.ParseFromString(ser)
            for follower in f.followers:
                if follower.follower_guid == guid:
                    f.follower.remove(follower)
        cursor.execute('''INSERT OR REPLACE INTO followers(id, serializedFollowers) VALUES (?,?)''', (1, f.SerializeToString()))
        self.db.commit()

    def get_followers(self):
        cursor = self.db.cursor()
        cursor.execute('''SELECT serializedFollowers FROM followers WHERE id=1''')
        proto = cursor.fetchone()
        if not proto:
            return None
        else:
            return proto[0]