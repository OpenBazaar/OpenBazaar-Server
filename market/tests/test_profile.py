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
        s = u.SocialAccount()
        s.username = "test_fb_username"
        s.type = s.SocialType.Value("FACEBOOK")
        u.social.extend([s])
        self.db.ProfileStore().set_proto(u.SerializeToString())

    def tearDown(self):
        os.remove("test.db")

    def test_MarketProfile_get_success(self):
        p = Profile(self.db).get()
        self.assertEqual('test_name', p.name)
        self.assertEqual(2, p.location)
        self.assertEqual('hello world', p.about)
        self.assertEqual(1, len(p.social))
        self.assertEqual(1, p.social[0].type)
        self.assertEqual('test_fb_username', p.social[0].username)

    def test_MarketProfile_remove_field_success(self):
        p = Profile(self.db)
        p.remove_field("about")
        user = p.get()
        self.assertEqual('test_name', user.name)
        self.assertEqual('', user.about)

    def test_MarketProfile_remove_social(self):
        p = Profile(self.db)
        p.remove_social_account("FACEBOOK")
        u = p.get()
        self.assertEqual(0, len(u.social))

    def test_MarketProfile_remove_lowercase_social(self):
        p = Profile(self.db)
        p.remove_social_account("facebook")
        u = p.get()
        self.assertEqual(0, len(u.social))

    def test_MarketProfile_remove_social_invalid(self):
        p = Profile(self.db)
        p.remove_social_account("TEST")
        u = p.get()
        self.assertEqual(1, len(u.social))

    def test_MarketProfile_add_social_no_proof(self):
        p = Profile(self.db)
        p.add_social_account("TWITTER", "test_twitter_username")
        u = p.get()
        self.assertEqual(2, len(u.social))
        self.assertEqual(1, u.social[0].type)
        self.assertEqual('test_fb_username', u.social[0].username)
        self.assertEqual(2, u.social[1].type)
        self.assertEqual('test_twitter_username', u.social[1].username)

    def test_MarketProfile_replace_social_no_proof(self):
        p = Profile(self.db)
        p.add_social_account("FACEBOOK", "test_updated_username")
        u = p.get()
        self.assertEqual(1, len(u.social))
        self.assertEqual(1, u.social[0].type)
        self.assertEqual('test_updated_username', u.social[0].username)

    def test_MarketProfile_add_social_with_proof(self):
        p = Profile(self.db)
        p.add_social_account("TWITTER", "test_twitter_username",
                                "http://test_url")
        u = p.get()
        self.assertEqual(2, len(u.social))
        self.assertEqual(1, u.social[0].type)
        self.assertEqual('test_fb_username', u.social[0].username)
        self.assertEqual('', u.social[0].proof_url)
        self.assertEqual(2, u.social[1].type)
        self.assertEqual('test_twitter_username', u.social[1].username)
        self.assertEqual('http://test_url', u.social[1].proof_url)

    def test_MarketProfile_replace_social_with_proof(self):
        p = Profile(self.db)
        p.add_social_account("FACEBOOK", "test_updated_username", "http://fb_url")
        u = p.get()
        self.assertEqual(1, len(u.social))
        self.assertEqual(1, u.social[0].type)
        self.assertEqual('test_updated_username', u.social[0].username)
        self.assertEqual('http://fb_url', u.social[0].proof_url)

    def test_MarketProfile_add_social_invalid(self):
        p = Profile(self.db)
        p.add_social_account("TEST", "test_twitter_username")
        u = p.get()
        self.assertEqual(1, len(u.social))
        self.assertEqual(1, u.social[0].type)
        self.assertEqual('test_fb_username', u.social[0].username)
