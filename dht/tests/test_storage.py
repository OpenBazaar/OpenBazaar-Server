__author__ = 'chris'
from twisted.trial import unittest

from dht.utils import digest
from dht.storage import ForgetfulStorage, PersistentStorage, TTLDict
from dht.kprotocol import Value

class ForgetFulStorageTest(unittest.TestCase):
    def test_setitem(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        f = ForgetfulStorage()
        tdict = TTLDict(3)
        tdict[key] = value
        f[keyword] = (key, value)
        self.assertEqual(f.data[keyword], tdict)

    def test_getitem(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        f = ForgetfulStorage()
        tdict = TTLDict(3)
        tdict[key] = value
        f[keyword] = (key, value)
        self.assertEqual(tdict, f[keyword])

    def test_get(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        v = Value()
        v.contractID = key
        v.serializedNode = value
        testv = [v.SerializeToString()]
        f = ForgetfulStorage()
        f[keyword] = (key, value)
        self.assertEqual(testv, f.get(keyword))

    def test_getSpecific(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        f = ForgetfulStorage()
        f[keyword] = (key, value)
        self.assertEqual(value, f.getSpecific(keyword, key))

    def test_delete(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        f = ForgetfulStorage()
        f[keyword] = (key, value)
        f.delete(keyword, key)
        self.assertEqual(f.get(keyword), None)

    def test_iterkeys(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        f = ForgetfulStorage()
        f[keyword] = (key, value)
        for k in f.iterkeys():
            self.assertEqual(k, keyword)

    def test_iteritems(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        f = ForgetfulStorage()
        f[keyword] = (key, value)
        for k, v in f.iteritems(keyword):
            self.assertEqual((key, value), (k, v))