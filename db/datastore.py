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
        return cursor.fetchone()[0]

    def delete(self, hash):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM hashmap WHERE hash = ?''', (hash,))
        self.db.commit()