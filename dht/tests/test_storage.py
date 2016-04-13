__author__ = 'chris'
from twisted.trial import unittest
from dht.utils import digest
from dht.storage import ForgetfulStorage
from protos.objects import Value


class ForgetfulStorageTest(unittest.TestCase):
    def setUp(self):
        self.keyword1 = digest("shoes")
        self.keyword2 = digest("socks")
        self.key1 = digest("contract1")
        self.key2 = digest("contract2")
        self.value = digest("node")

    def test_setitem(self):
        p = ForgetfulStorage()
        p[self.keyword1] = (self.key1, self.value, 10)
        p[self.keyword2] = (self.key1, self.value, 10)
        p[self.keyword2] = (self.key2, self.value, 10)
        self.assertEqual(p[self.keyword1][0][:2], (self.key1, self.value))
        ret = []
        for val in p[self.keyword2]:
            ret.append(val[:2])
        self.assertEqual(ret, [(self.key1, self.value), (self.key2, self.value)])

    def test_get(self):
        v = Value()
        v.valueKey = self.key1
        v.serializedData = self.value
        v.ttl = 10
        testv = [v.SerializeToString()]
        p = ForgetfulStorage()
        p[self.keyword1] = (self.key1, self.value, 10)
        self.assertEqual(testv, p.get(self.keyword1))

    def test_getSpecific(self):
        p = ForgetfulStorage()
        p[self.keyword1] = (self.key1, self.value, 10)
        self.assertEqual(self.value, p.getSpecific(self.keyword1, self.key1))

    def test_delete(self):
        p = ForgetfulStorage()
        p[self.keyword1] = (self.key1, self.value, 10)
        p.delete(self.keyword1, self.key1)
        self.assertEqual(p.get(self.keyword1), None)

    def test_iterkeys(self):
        p = ForgetfulStorage()
        p[self.keyword1] = (self.key1, self.value, 10)
        for k in p.iterkeys():
            self.assertEqual(k[0].decode("hex"), self.keyword1)

    def test_iteritems(self):
        p = ForgetfulStorage()
        p[self.keyword1] = (self.key1, self.value, 10)
        for k, v in p.iteritems(self.keyword1):
            self.assertEqual((self.key1, self.value), (k, v))

    def test_ttl(self):
        p = ForgetfulStorage()
        p[self.keyword1] = (self.key1, self.value, .000000000001)
        self.assertTrue(p.get(self.keyword1) is None)
