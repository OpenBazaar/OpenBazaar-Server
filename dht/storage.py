"""
Copyright (c) 2014 Brian Muller
Copyright (c) 2015 OpenBazaar
"""

import time
import sqlite3 as lite
from collections import OrderedDict, MutableMapping
from zope.interface import implements, Interface
from protos.objects import Value
from threading import RLock


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
        """
        By default, max age is a week.
        """
        self.data = OrderedDict()
        self.ttl = ttl

    def __setitem__(self, keyword, values):
        valueDic = TTLDict(self.ttl)
        if keyword in self.data:
            valueDic = self.data[keyword]
            if values[0] not in valueDic:
                valueDic[values[0]] = values[1]
                valueDic.set_ttl(values[0], values[2])
        else:
            valueDic[values[0]] = values[1]
            valueDic.set_ttl(values[0], values[2])
            self.data[keyword] = valueDic
        self.cull()

    def cull(self):
        for key in self.data.iterkeys():
            self.data[key].cull()
            if len(self.data[key]) == 0:
                del self.data[key]

    def get(self, keyword, default=None):
        self.cull()
        if keyword in self.data:
            ret = []
            for k, v in self[keyword].items():
                value = Value()
                value.valueKey = k
                value.serializedData = v
                value.ttl = int(round(self.data[keyword].get_ttl(k)))
                ret.append(value.SerializeToString())
            return ret
        return default

    def getSpecific(self, keyword, key):
        self.cull()
        if keyword in self.data and key in self.data[keyword]:
            return self.data[keyword][key]

    def delete(self, keyword, key):
        del self.data[keyword][key]
        self.cull()

    def __getitem__(self, keyword):
        self.cull()
        return self.data[keyword]

    def __iter__(self):
        self.cull()
        return iter(self.data)

    def __repr__(self):
        self.cull()
        return repr(self.data)

    def iterkeys(self):
        self.cull()
        return self.data.iterkeys()

    def iteritems(self, keyword):
        self.cull()
        return self.data[keyword].iteritems()

    def get_ttl(self, keyword, key):
        if keyword in self.data and key in self.data[keyword]:
            return self.data[keyword].get_ttl(key)


class PersistentStorage(object):
    implements(IStorage)

    def __init__(self, filename, ttl=604800):

        self.ttl = ttl
        self.db = lite.connect(filename)
        self.db.text_factory = str
        try:
            cursor = self.db.cursor()
            cursor.execute('''CREATE TABLE dht(keyword TEXT, id BLOB, value BLOB, birthday FLOAT)''')
            cursor.execute('''CREATE INDEX idx1 ON dht(keyword);CREATE INDEX idx2 ON dht(birthday);''')
            self.db.commit()
        except Exception:
            self.cull()

    def __setitem__(self, keyword, values):
        cursor = self.db.cursor()
        cursor.execute('''SELECT id, value FROM dht WHERE keyword=? AND id=? AND value=?''',
                       (keyword.encode("hex"), values[0], values[1]))
        if cursor.fetchone() is None:
            birthday = time.time() - (self.ttl - values[2])
            cursor.execute('''INSERT OR IGNORE INTO dht(keyword, id, value, birthday)
                          VALUES (?,?,?,?)''', (keyword.encode("hex"), values[0], values[1], birthday))
            self.db.commit()
        self.cull()

    def __getitem__(self, keyword):
        self.cull()
        cursor = self.db.cursor()
        cursor.execute('''SELECT id, value, birthday FROM dht WHERE keyword=?''', (keyword.encode("hex"),))
        return cursor.fetchall()

    def get(self, keyword, default=None):
        self.cull()
        if len(self[keyword]) > 0:
            ret = []
            for k, v, birthday in self[keyword]:
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
            cursor.execute('''SELECT keyword FROM dht''')
            keywords = cursor.fetchall()
            keyword_list = []
            for k in keywords:
                if k[0].decode("hex") not in keyword_list:
                    keyword_list.append(k[0].decode("hex"))
            return keyword_list.__iter__()
        except Exception:
            return None

    def iteritems(self, keyword):
        self.cull()
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


class TTLDict(MutableMapping):
    """
    Dictionary with TTL
    Extra args and kwargs are passed to initial .update() call
    """

    def __init__(self, default_ttl, *args, **kwargs):
        self._default_ttl = default_ttl
        self._values = {}
        self._lock = RLock()
        self.update(*args, **kwargs)

    def __repr__(self):
        return '<TTLDict@%#08x; ttl=%r, v=%r;>' % (id(self), self._default_ttl, self._values)

    def set_ttl(self, key, ttl, now=None):
        """ Set TTL for the given key """
        if now is None:
            now = time.time()
        with self._lock:
            # pylint: disable=unused-variable
            _expire, value = self._values[key]
            self._values[key] = (now + ttl, value)

    def get_ttl(self, key, now=None):
        """ Return remaining TTL for a key """
        if now is None:
            now = time.time()
        with self._lock:
            # pylint: disable=unused-variable
            expire, _value = self._values[key]
            return expire - now

    def expire_at(self, key, timestamp):
        """ Set the key expire timestamp """
        with self._lock:
            # pylint: disable=unused-variable
            _expire, value = self._values[key]
            self._values[key] = (timestamp, value)

    def is_expired(self, key, now=None, remove=False):
        """ Check if key has expired """
        with self._lock:
            if now is None:
                now = time.time()
            # pylint: disable=unused-variable
            expire, _value = self._values[key]
            if expire is None:
                return False
            expired = expire < now
            if expired and remove:
                self.__delitem__(key)
            return expired

    def __len__(self):
        with self._lock:
            for key in self._values.keys():
                self.is_expired(key, remove=True)
            return len(self._values)

    def __iter__(self):
        with self._lock:
            for key in self._values.keys():
                if not self.is_expired(key, remove=True):
                    yield key

    def __setitem__(self, key, value):
        with self._lock:
            if self._default_ttl is None:
                expire = None
            else:
                expire = time.time() + self._default_ttl
            self._values[key] = (expire, value)

    def __delitem__(self, key):
        with self._lock:
            del self._values[key]

    def __getitem__(self, key):
        with self._lock:
            self.is_expired(key, remove=True)
            return self._values[key][1]

    def cull(self):
        with self._lock:
            for key in self._values.keys():
                self.is_expired(key, remove=True)
