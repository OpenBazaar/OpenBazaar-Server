__author__ = 'chris'
import time

from twisted.trial import unittest
from twisted.internet import reactor, task

from dht.utils import digest
from dht.storage import ForgetfulStorage, PersistentStorage, TTLDict

from protos.objects import Value


class ForgetFulStorageTest(unittest.TestCase):
    def setUp(self):
        self.keyword1 = digest("shoes")
        self.keyword2 = digest("socks")
        self.key1 = digest("contract1")
        self.key2 = digest("contract2")
        self.value = digest("node")

    def test_setitem(self):
        f = ForgetfulStorage()
        tdict1 = TTLDict(3)
        tdict1[self.key1] = self.value
        f[self.keyword1] = (self.key1, self.value)
        tdict2 = TTLDict(3)
        tdict2[self.key1] = self.value
        tdict2[self.key2] = self.value
        f[self.keyword2] = (self.key1, self.value)
        f[self.keyword2] = (self.key2, self.value)
        self.assertEqual(f.data[self.keyword1], tdict1)
        self.assertEqual(f.data[self.keyword2], tdict2)

    def test_getitem(self):
        f = ForgetfulStorage()
        tdict = TTLDict(3)
        tdict[self.key1] = self.value
        f[self.keyword1] = (self.key1, self.value)
        self.assertEqual(tdict, f[self.keyword1])

    def test_get(self):
        v = Value()
        v.valueKey = self.key1
        v.serializedData = self.value
        testv = [v.SerializeToString()]
        f = ForgetfulStorage()
        f[self.keyword1] = (self.key1, self.value)
        self.assertEqual(testv, f.get(self.keyword1))

    def test_getSpecific(self):
        f = ForgetfulStorage()
        f[self.keyword1] = (self.key1, self.value)
        self.assertEqual(self.value, f.getSpecific(self.keyword1, self.key1))

    def test_delete(self):
        f = ForgetfulStorage()
        f[self.keyword1] = (self.key1, self.value)
        f.delete(self.keyword1, self.key1)
        self.assertEqual(f.get(self.keyword1), None)

    def test_iterkeys(self):
        f = ForgetfulStorage()
        f[self.keyword1] = (self.key1, self.value)
        for k in f.iterkeys():
            self.assertEqual(k, self.keyword1)

    def test_iteritems(self):
        f = ForgetfulStorage()
        f[self.keyword1] = (self.key1, self.value)
        for k, v in f.iteritems(self.keyword1):
            self.assertEqual((self.key1, self.value), (k, v))

    def test_ttl(self):
        f = ForgetfulStorage(ttl=.00000000000001)
        f[self.keyword1] = (self.key1, self.value)
        self.assertTrue(self.keyword1 not in f)


class PersistentStorageTest(unittest.TestCase):
    def setUp(self):
        self.keyword1 = digest("shoes")
        self.keyword2 = digest("socks")
        self.key1 = digest("contract1")
        self.key2 = digest("contract2")
        self.value = digest("node")

    def test_setitem(self):
        p = PersistentStorage(":memory:")
        p[self.keyword1] = (self.key1, self.value)
        p[self.keyword2] = (self.key1, self.value)
        p[self.keyword2] = (self.key2, self.value)
        self.assertEqual(p[self.keyword1], [(self.key1, self.value)])
        self.assertEqual(p[self.keyword2], [(self.key1, self.value), (self.key2, self.value)])

    def test_get(self):
        v = Value()
        v.valueKey = self.key1
        v.serializedData = self.value
        testv = [v.SerializeToString()]
        p = PersistentStorage(":memory:")
        p[self.keyword1] = (self.key1, self.value)
        self.assertEqual(testv, p.get(self.keyword1))

    def test_getSpecific(self):
        p = PersistentStorage(":memory:")
        p[self.keyword1] = (self.key1, self.value)
        self.assertEqual(self.value, p.getSpecific(self.keyword1, self.key1))

    def test_delete(self):
        p = PersistentStorage(":memory:")
        p[self.keyword1] = (self.key1, self.value)
        p.delete(self.keyword1, self.key1)
        self.assertEqual(p.get(self.keyword1), None)

    def test_iterkeys(self):
        p = PersistentStorage(":memory:")
        p[self.keyword1] = (self.key1, self.value)
        for k in p.iterkeys():
            self.assertEqual(k, self.keyword1)

    def test_iteritems(self):
        p = PersistentStorage(":memory:")
        p[self.keyword1] = (self.key1, self.value)
        for k, v in p.iteritems(self.keyword1):
            self.assertEqual((self.key1, self.value), (k, v))

    def test_ttl(self):
        p = PersistentStorage(":memory:", ttl=.000000000001)
        p[self.keyword1] = (self.key1, self.value)
        self.assertTrue(p.get(self.keyword1) is None)


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
        self.assertTrue(ttl_dict.is_expired('a', now=now + 61))

        # remove=False, so nothing should be gone
        self.assertEqual(len(ttl_dict), 2)
