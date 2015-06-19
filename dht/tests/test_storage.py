__author__ = 'chris'
from twisted.trial import unittest
from twisted.internet import reactor, task

from dht.utils import digest
from dht.storage import ForgetfulStorage, PersistentStorage, TTLDict
from dht.kprotocol import Value

class ForgetFulStorageTest(unittest.TestCase):
    def test_setitem(self):
        keyword1 = digest("shoes")
        keyword2 = digest("socks")
        key1 = digest("contract1")
        key2 = digest("contract2")
        value = digest("node")
        f = ForgetfulStorage()
        tdict1 = TTLDict(3)
        tdict1[key1] = value
        f[keyword1] = (key1, value)
        tdict2 = TTLDict(3)
        tdict2[key1] = value
        tdict2[key2] = value
        f[keyword2] = (key1, value)
        f[keyword2] = (key2, value)
        self.assertEqual(f.data[keyword1], tdict1)
        self.assertEqual(f.data[keyword2], tdict2)

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

    def test_ttl(self):
        def test_expired():
            self.assertTrue(keyword not in f)
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        f = ForgetfulStorage(ttl=.0001)
        f[keyword] = (key, value)
        return task.deferLater(reactor, .0002, test_expired)

class PersistentStorageTest(unittest.TestCase):
    def test_setitem(self):
        keyword1 = digest("shoes")
        keyword2 = digest("socks")
        key1 = digest("contract1")
        key2 = digest("contract2")
        value = digest("node")
        p = PersistentStorage(":memory:")
        p[keyword1] = (key1, value)
        p[keyword2] = (key1, value)
        p[keyword2] = (key2, value)
        self.assertEqual(p[keyword1], [(key1, value)])
        self.assertEqual(p[keyword2], [(key1, value), (key2, value)])

    def test_get(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        v = Value()
        v.contractID = key
        v.serializedNode = value
        testv = [v.SerializeToString()]
        p = PersistentStorage(":memory:")
        p[keyword] = (key, value)
        self.assertEqual(testv, p.get(keyword))

    def test_getSpecific(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        p = PersistentStorage(":memory:")
        p[keyword] = (key, value)
        self.assertEqual(value, p.getSpecific(keyword, key))

    def test_delete(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        p = PersistentStorage(":memory:")
        p[keyword] = (key, value)
        p.delete(keyword, key)
        self.assertEqual(p.get(keyword), None)

    def test_iterkeys(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        p = PersistentStorage(":memory:")
        p[keyword] = (key, value)
        for k in p.iterkeys():
            self.assertEqual(k, keyword)

    def test_iteritems(self):
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        p = PersistentStorage(":memory:")
        p[keyword] = (key, value)
        for k, v in p.iteritems(keyword):
            self.assertEqual((key, value), (k, v))

    def test_ttl(self):
        def test_expired():
            self.assertTrue(p.get(keyword) is None)
        keyword = digest("shoes")
        key = digest("contract")
        value = digest("node")
        p = PersistentStorage(":memory:", ttl=.0001)
        p[keyword] = (key, value)
        return task.deferLater(reactor, .0002, test_expired)