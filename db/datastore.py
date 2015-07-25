__author__ = 'chris'
import sqlite3 as lite
from constants import DATABASE

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

    def delete(self, hash):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM hashmap WHERE hash = ?''', (hash,))
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