import hashlib

from twisted.trial import unittest
from twisted.internet import defer

from dht.utils import digest, sharedPrefix, OrderedSet, deferredDict


class UtilsTest(unittest.TestCase):
    def test_digest(self):
        intermed = hashlib.sha256("1").digest()
        d = hashlib.new('ripemd160', intermed).digest()
        self.assertEqual(d, digest(1))

        intermed = hashlib.sha256("another").digest()
        d = hashlib.new('ripemd160', intermed).digest()
        self.assertEqual(d, digest('another'))

    def test_sharedPrefix(self):
        args = ['prefix', 'prefixasdf', 'prefix', 'prefixxxx']
        self.assertEqual(sharedPrefix(args), 'prefix')

        args = ['p', 'prefixasdf', 'prefix', 'prefixxxx']
        self.assertEqual(sharedPrefix(args), 'p')

        args = ['one', 'two']
        self.assertEqual(sharedPrefix(args), '')

        args = ['hi']
        self.assertEqual(sharedPrefix(args), 'hi')

    def test_defferedDict(self):
        def checkValues(d):
            self.assertTrue(isinstance(d, dict))
            self.assertTrue(len(d) == 3)

        def checkEmpty(d):
            self.assertTrue(isinstance(d, dict))
            self.assertTrue(len(d) == 0)

        ds = {}
        ds["key1"] = defer.Deferred()
        ds["key2"] = defer.Deferred()
        ds["key3"] = defer.Deferred()
        deferredDict(ds).addCallback(checkValues)
        for v in ds.itervalues():
            v.callback("True")
        deferredDict({}).addCallback(checkEmpty)


class OrderedSetTest(unittest.TestCase):
    def test_order(self):
        o = OrderedSet()
        o.push('1')
        o.push('1')
        o.push('2')
        o.push('1')
        self.assertEqual(o, ['2', '1'])
