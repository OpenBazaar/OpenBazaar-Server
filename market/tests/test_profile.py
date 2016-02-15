from twisted.trial import unittest
from twisted.python import log
from protos import objects
import os

from db.datastore import Database
from market.profile import Profile

class MarketProfileTest(unittest.TestCase):
    def setUp(self):
        self.catcher = []
        observer = self.catcher.append
        log.addObserver(observer)
        self.addCleanup(log.removeObserver, observer)
        self.db = Database(filepath="test.db")
        self.createTestUser()

    def createTestUser(self):
        u = objects.Profile()
        u.name = "test_name"
        u.location = 2
        u.about = "hello world"
        self.db.ProfileStore().set_proto(u.SerializeToString())

    def tearDown(self):
        os.remove("test.db")

    def test_MarketProfile_get_success(self):
        p = Profile(self.db).get()
        self.assertEqual('test_name', p.name)
        self.assertEqual(2, p.location)
        self.assertEqual('hello world', p.about)
