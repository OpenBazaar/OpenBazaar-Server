import os
import unittest

from db.datastore import Database
from dht.utils import digest
from protos.objects import Profile, Listings, Following, Metadata, Followers, Node, FULL_CONE
from protos.countries import CountryCode

class DatastoreTest(unittest.TestCase):
    def setUp(self):

        self.db = Database(filepath="test.db")
        self.test_hash = "87e0555568bf5c7e4debd6645fc3f41e88df6ca8"
        self.test_hash2 = "97e0555568bf5c7e4debd6645fc3f41e88df6ca8"
        self.test_file = "Contents of test.txt"
        self.test_file2 = "Contents of test2.txt"

        self.sp = Profile()
        self.key = Profile().PublicKey()
        self.key.public_key = "Key"
        self.key.signature = "Sig"
        self.sp.name = "Test User"
        self.sp.encryption_key.MergeFrom(self.key)
        self.sp.location = CountryCode.Value('UNITED_STATES')

        self.serialized_listings = Listings()
        self.lm = self.serialized_listings.ListingMetadata()
        self.lm.contract_hash = self.test_hash
        self.lm.title = "TEST CONTRACT TITLE"
        self.lm.price = 0
        self.lm.currency_code = "USD"
        self.lm.nsfw = False
        self.lm.origin = CountryCode.Value('ALL')

        self.u = Following.User()
        self.u.guid = '0000000000000000000000000000000000'
        self.u.signed_pubkey = 'signed_pubkey'

        self.m = Metadata()
        self.m.name = 'Test User'
        self.m.handle = '@TestUser'
        self.m.avatar_hash = ''
        self.m.nsfw = False
        self.u.metadata.MergeFrom(self.m)

        self.f = Followers.Follower()
        self.f.guid = '0000000000000000000000000000000001'
        self.f.following = ''
        self.f.signed_pubkey = ''
        self.f.metadata.MergeFrom(self.m)

        self.hm = self.db.HashMap()
        self.hm.delete_all()

        self.ps = self.db.ProfileStore()
        self.ls = self.db.ListingsStore()
        self.ks = self.db.KeyStore()
        self.fd = self.db.FollowData()
        self.ms = self.db.MessageStore()
        self.ns = self.db.NotificationStore()
        self.vs = self.db.VendorStore()

    def tearDown(self):
        os.remove("test.db")

    def test_hashmapInsert(self):
        self.hm.insert(self.test_hash, self.test_file)
        f = self.hm.get_file(self.test_hash)
        self.assertEqual(f, self.test_file)

    def test_hashmapDelete(self):
        self.hm.insert(self.test_hash, self.test_file)
        f = self.hm.get_file(self.test_hash)
        self.assertEqual(f, self.test_file)
        self.hm.delete(self.test_hash)
        v = self.hm.get_file(self.test_hash)
        self.assertIsNone(v)

    def test_hashmapGetEmpty(self):
        f = self.hm.get_file('87e0555568bf5c7e4debd6645fc3f41e88df6ca9')
        self.assertEqual(f, None)

    def test_hashmapGetAll(self):
        # Get All from empty datastore
        self.hm.delete_all()
        f = self.hm.get_all()
        self.assertEqual(0, len(f))

        # Get All from populated datastore
        self.hm.insert(self.test_hash, self.test_file)
        self.hm.insert(self.test_hash2, self.test_file2)
        f = self.hm.get_all()

        self.assertIn((self.test_hash, self.test_file), f)
        self.assertIn((self.test_hash2, self.test_file2), f)

    def test_setProto(self):
        self.ps.set_proto(self.sp.SerializeToString())
        sp = self.ps.get_proto()
        val = Profile()
        val.ParseFromString(sp)
        self.assertEqual(self.sp, val)

    def test_addListing(self):
        self.ls.delete_all_listings()
        self.ls.add_listing(self.lm)
        self.ls.add_listing(self.lm)

        l = self.ls.get_proto()
        val = Listings()
        val.ParseFromString(l)
        self.assertEqual(self.lm, val.listing[0])
        self.assertEqual(1, len(val.listing))

    def test_deleteListing(self):
        self.ls.delete_all_listings()
        self.ls.add_listing(self.lm)
        self.ls.delete_listing(self.test_hash)
        l = self.ls.get_proto()
        val = Listings()
        val.ParseFromString(l)
        self.assertEqual(0, len(val.listing))

        # Try to delete when table is already empty
        self.ls.delete_all_listings()
        self.assertEqual(None, self.ls.delete_listing(self.test_hash))

    def test_setGUIDKey(self):
        self.ks.set_key("guid", "privkey", "signed_privkey")
        key = self.ks.get_key("guid")
        self.assertEqual(("privkey", "signed_privkey"), key)

    def test_setBitcoinKey(self):
        self.ks.set_key("bitcoin", "privkey", "signed_privkey")
        key = self.ks.get_key("bitcoin")
        self.assertEqual(("privkey", "signed_privkey"), key)

    def test_getKeyFromEmptyTable(self):
        self.ks.delete_all_keys()
        self.assertEqual(None, self.ks.get_key("guid"))

    def test_follow_unfollow(self):
        self.fd.follow(self.u)
        following = self.fd.get_following()
        self.assertIsNotNone(following)

        self.fd.follow(self.u)
        self.assertTrue(self.fd.is_following(self.u.guid))

        self.fd.unfollow(self.u.guid)
        self.fd.unfollow(self.f)
        following = self.fd.get_following()
        self.assertEqual(following, '')
        self.assertFalse(self.fd.is_following(self.u.guid))

    def test_deleteFollower(self):
        self.fd.set_follower(self.f)
        self.fd.set_follower(self.f)
        f = self.fd.get_followers()
        self.assertIsNotNone(f)
        self.fd.delete_follower(self.f.guid)
        f = self.fd.get_followers()
        self.assertEqual(f, '')

    def test_convesations(self):
        conversations = self.ms.get_conversations()
        self.assertTrue(len(conversations) == 0)
        self.ms.save_message(self.u.guid, self.m.handle, self.u.signed_pubkey,
                             '', 'SUBJECT', 'CHAT', 'MESSAGE', '0000-00-00 00:00:00',
                             '', '', '0')
        # msgs = self.ms.get_unread()
        # self.assertEqual(1, len(msgs))

        # self.ms.mark_as_read(self.u.guid)
        # msgs = self.ms.get_unread()
        # self.assertEqual(0, len(msgs))

        conversations = self.ms.get_conversations()
        self.assertIsNotNone(conversations)

    def test_saveMessage(self):
        msgs = self.ms.get_messages(self.u.guid, 'CHAT')
        self.assertTrue(len(msgs) == 0)
        self.ms.save_message(self.u.guid, self.m.handle, self.u.signed_pubkey,
                             '', 'SUBJECT', 'CHAT', 'MESSAGE', '0000-00-00 00:00:00',
                             '', '', '')
        msgs = self.ms.get_messages(self.u.guid, 'CHAT')
        self.assertIsNotNone(msgs)
        self.ms.delete_message(self.u.guid)
        msgs = self.ms.get_messages(self.u.guid, 'CHAT')
        self.assertTrue(len(msgs) == 0)

    def test_notificationStore(self):
        n = self.ns.get_notifications()
        self.assertTrue(len(n) == 0)
        self.ns.save_notification("1234", self.u.guid, self.m.handle, 'NOTICE', "", ""
                                  '0000-00-00 00:00:00', '', 0)
        n = self.ns.get_notifications()
        self.assertIsNotNone(n)
        self.ns.mark_as_read("1234")

        self.ns.delete_notification("1234")
        n = self.ns.get_notifications()
        self.assertTrue(len(n) == 0)

    def test_vendorStore(self):
        v = self.vs.get_vendors()
        self.assertEqual(v, [])
        addr = Node.IPAddress()
        addr.ip = "127.0.0.1"
        addr.port = 1234
        n = Node()
        n.guid = digest("abcdefg")
        n.signedPublicKey = digest("signed pubkey")
        n.nodeAddress.MergeFrom(addr)
        n.natType = FULL_CONE
        self.vs.save_vendor(self.u.guid, n.SerializeToString())
        v = self.vs.get_vendors()
        self.assertIsNot(v, [])
        self.vs.delete_vendor(self.u.guid)
        v = self.vs.get_vendors()
        self.assertEqual(v, [])
