__author__ = 'chris'
import time

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

class TTLDictTest(unittest.TestCase):
    """ TTLDict tests """
    def test_update_no_ttl(self):
        """ Test update() call """
        ttl_dict = TTLDict(None)
        orig_dict = {'hello': 'world', 'intval': 3}
        ttl_dict.update(orig_dict)
        self.assertEqual(sorted(orig_dict.items()), sorted(ttl_dict.items()))

    def test_len_clears_expired_items(self):
        """ Test that calling len() removes expired items """
        ttl_dict = TTLDict(-1, a=1, b=2)
        self.assertEqual(ttl_dict._values.keys(), sorted(['a', 'b']))
        self.assertEqual(len(ttl_dict), 0)
        self.assertEqual(ttl_dict._values.keys(), [])

    def test_expire_at(self):
        """ Test expire_at """
        ttl_dict = TTLDict(60)
        ttl_dict['a'] = 100
        ttl_dict['b'] = 123
        self.assertEqual(ttl_dict['a'], 100)
        self.assertEqual(ttl_dict['b'], 123)
        self.assertEqual(len(ttl_dict), 2)
        ttl_dict.expire_at('a', time.time())
        self.assertRaises(KeyError, lambda: ttl_dict['a'])
        self.assertEqual(len(ttl_dict), 1)
        self.assertEqual(ttl_dict['b'], 123)

    def test_set_ttl_get_ttl(self):
        """ Test set_ttl() and get_ttl() """
        ttl_dict = TTLDict(120, foo=3, bar=None)
        self.assertEqual(sorted(ttl_dict), ['bar', 'foo'])
        self.assertEqual(ttl_dict['foo'], 3)
        self.assertEqual(ttl_dict['bar'], None)
        self.assertEqual(len(ttl_dict), 2)
        ttl_dict.set_ttl('foo', 3)
        ttl_foo = ttl_dict.get_ttl('foo')
        self.assertTrue(ttl_foo <= 3.0)
        ttl_bar = ttl_dict.get_ttl('bar')
        self.assertTrue(ttl_bar - ttl_foo > 100)

    def test_set_ttl_key_error(self):
        """ Test that set_ttl() raises KeyError """
        ttl_dict = TTLDict(60)
        self.assertRaises(KeyError, ttl_dict.set_ttl, 'missing', 10)

    def test_get_ttl_key_error(self):
        """ Test that get_ttl() raises KeyError """
        ttl_dict = TTLDict(60)
        self.assertRaises(KeyError, ttl_dict.get_ttl, 'missing')

    def test_iter_empty(self):
        """ Test that empty TTLDict can be iterated """
        ttl_dict = TTLDict(60)
        for key in ttl_dict:
            self.fail("Iterating empty dictionary gave a key %r" % (key,))

    def test_iter(self):
        """ Test that TTLDict can be iterated """
        ttl_dict = TTLDict(60)
        ttl_dict.update(zip(range(10), range(10)))
        self.assertEqual(len(ttl_dict), 10)
        for key in ttl_dict:
            self.assertEqual(key, ttl_dict[key])

    def test_is_expired(self):
        """ Test is_expired() call """
        now = time.time()
        ttl_dict = TTLDict(60, a=1, b=2)
        self.assertFalse(ttl_dict.is_expired('a'))
        self.assertFalse(ttl_dict.is_expired('a', now=now))
        self.assertTrue(ttl_dict.is_expired('a', now=now+61))

        # remove=False, so nothing should be gone
        self.assertEqual(len(ttl_dict), 2)