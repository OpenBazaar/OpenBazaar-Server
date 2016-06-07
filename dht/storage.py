"""
Copyright (c) 2014 Brian Muller
Copyright (c) 2015 OpenBazaar
"""

import time
import sqlite3 as lite
from zope.interface import implements, Interface
from protos.objects import Value


class IStorage(Interface):
    """
    Local storage for this node.
    """

    def __setitem__(self, key, value):
        """
        Set a key to the given value.
        """

    def __getitem__(self, key):
        """
        Get the given key.  If item doesn't exist, raises C{KeyError}
        """

    def get(self, key, default=None):
        """
        Get given key.  If not found, return default.
        """

    def getSpecific(self, keyword, key):
        """
        Return the exact value for a given keyword and key.
        """

    def cull(self):
        """
        Iterate over all keys and remove expired items
        """

    def delete(self, keyword, key):
        """
        Delete the value stored at keyword/key.
        """

    def iterkeys(self):
        """
        Get the key iterator for this storage, should yield a list of keys
        """

    def iteritems(self, keyword):
        """
        Get the value iterator for the given keyword, should yield a tuple of (key, value)
        """

    def get_ttl(self, keyword, key):
        """
        Get the remaining time for a given key.
        """


class ForgetfulStorage(object):
    implements(IStorage)

    def __init__(self, ttl=604800):

        self.ttl = ttl
        self.db = lite.connect(":memory:")
        self.db.text_factory = str
        cursor = self.db.cursor()
        cursor.execute('''CREATE TABLE dht(keyword TEXT, id BLOB, value BLOB, birthday FLOAT)''')
        cursor.execute('''CREATE INDEX idx1 ON dht(keyword);''')
        cursor.execute('''CREATE INDEX idx2 ON dht(birthday);''')
        self.db.commit()

    def __setitem__(self, keyword, values):
        keyword = keyword.encode("hex")
        cursor = self.db.cursor()
        birthday = time.time() - (self.ttl - values[2])
        cursor.execute('''INSERT INTO dht(keyword, id, value, birthday)
                      SELECT ?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM dht WHERE keyword=? AND id=?)''',
                       (keyword, values[0], values[1], birthday, keyword, values[0]))
        self.db.commit()

    def __getitem__(self, keyword):
        self.cull()
        cursor = self.db.cursor()
        cursor.execute('''SELECT id, value, birthday FROM dht WHERE keyword=?''', (keyword.encode("hex"),))
        return cursor.fetchall()

    def get(self, keyword, default=None):
        self.cull()
        kw = self[keyword]
        if len(kw) > 0:
            ret = []
            for k, v, birthday in kw:
                value = Value()
                value.valueKey = k
                value.serializedData = v
                value.ttl = int(round(self.ttl - (time.time() - birthday)))
                ret.append(value.SerializeToString())
            return ret
        return default

    def getSpecific(self, keyword, key):
        try:
            cursor = self.db.cursor()
            cursor.execute('''SELECT value FROM dht WHERE keyword=? AND id=?''', (keyword.encode("hex"), key))
            return cursor.fetchone()[0]
        except Exception:
            return None

    def cull(self):
        expiration = time.time() - self.ttl
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM dht WHERE birthday < ?''', (expiration,))
        self.db.commit()

    def delete(self, keyword, key):
        try:
            cursor = self.db.cursor()
            cursor.execute('''DELETE FROM dht WHERE keyword=? AND id=?''', (keyword.encode("hex"), key))
            self.db.commit()
        except Exception:
            pass
        self.cull()

    def iterkeys(self):
        self.cull()
        try:
            cursor = self.db.cursor()
            cursor.execute('''SELECT DISTINCT keyword FROM dht''')
            keywords = cursor.fetchall()
            return keywords.__iter__()
        except Exception:
            return None

    def iteritems(self, keyword):
        try:
            cursor = self.db.cursor()
            cursor.execute('''SELECT id, value FROM dht WHERE keyword=?''', (keyword.encode("hex"),))
            return cursor.fetchall().__iter__()
        except Exception:
            return None

    def get_ttl(self, keyword, key):
        cursor = self.db.cursor()
        cursor.execute('''SELECT birthday FROM dht WHERE keyword=? AND id=?''', (keyword.encode("hex"), key,))
        return self.ttl - (time.time() - cursor.fetchall()[0][0])

    def get_db_size(self):
        cursor = self.db.cursor()
        cursor.execute('''PRAGMA page_count;''')
        count = cursor.fetchone()[0]
        cursor.execute('''PRAGMA page_size;''')
        size = cursor.fetchone()[0]
        return count * size
