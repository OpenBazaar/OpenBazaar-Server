import os
import unittest
import time
from db.datastore import Database
from dht.utils import digest
from config import DATA_FOLDER
from protos.objects import Profile, Listings, Following, Metadata, Followers, Node, FULL_CONE
from protos.countries import CountryCode

ZERO_TIMESTAMP = '0000-00-00 00:00:00'


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
        self.sp.guid_key.MergeFrom(self.key)
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
        self.u.pubkey = 'signed_pubkey'

        self.m = Metadata()
        self.m.name = 'Test User'
        self.m.handle = '@TestUser'
        self.m.avatar_hash = ''
        self.m.nsfw = False
        self.u.metadata.MergeFrom(self.m)

        self.f = Followers.Follower()
        self.f.guid = '0000000000000000000000000000000001'
        self.f.following = ''
        self.f.pubkey = ''
        self.f.metadata.MergeFrom(self.m)

        self.hm = self.db.filemap
        self.hm.delete_all()

        self.ps = self.db.profile
        self.ls = self.db.listings
        self.ks = self.db.keys
        self.fd = self.db.follow
        self.ms = self.db.messages
        self.ns = self.db.notifications
        self.vs = self.db.vendors
        self.bs = self.db.broadcasts
        self.moderators = self.db.moderators
        self.purchases = self.db.purchases
        self.sales = self.db.sales
        self.settings = self.db.settings

    def tearDown(self):
        os.remove("test.db")

    def test_hashmapInsert(self):
        self.hm.insert(self.test_hash, self.test_file)
        f = self.hm.get_file(self.test_hash)
        self.assertEqual(f, DATA_FOLDER + self.test_file)

    def test_hashmapDelete(self):
        self.hm.insert(self.test_hash, self.test_file)
        f = self.hm.get_file(self.test_hash)
        self.assertEqual(f, DATA_FOLDER + self.test_file)
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

    def test_MassageStore(self):
        msgs = self.ms.get_messages(self.u.guid, 'CHAT')
        self.assertEqual(0, len(msgs))
        guids = self.ms.get_unread()
        self.assertEqual(0, len(guids))
        conversations = self.ms.get_conversations()
        self.assertEqual(0, len(conversations))

        self.ms.save_message(self.u.guid, self.m.handle, self.u.pubkey,
                             'SUBJECT', 'CHAT', 'MESSAGE', time.time(),
                             '', '', '')
        msgs = self.ms.get_messages(self.u.guid, 'CHAT')
        self.assertEqual(1, len(msgs))

        guids = self.ms.get_unread()
        self.assertEqual(1, len(guids))

        conversations = self.ms.get_conversations()
        self.assertEqual(1, len(conversations))

        self.ms.mark_as_read(self.u.guid)
        guids = self.ms.get_unread()
        self.assertEqual(0, len(guids))

        self.ms.delete_messages(self.u.guid)
        msgs = self.ms.get_messages(self.u.guid, 'CHAT')
        self.assertEqual(0, len(msgs))

    def test_BroadcastStore(self):
        bmsgs = self.bs.get_broadcasts()
        self.assertEqual(0, len(bmsgs))

        self.bs.save_broadcast('BID', self.u.guid, self.m.handle, 'MESSAGE', ZERO_TIMESTAMP, '')
        bmsgs = self.bs.get_broadcasts()
        self.assertEqual(1, len(bmsgs))

        self.bs.delete_broadcast('BID')
        bmsgs = self.bs.get_broadcasts()
        self.assertEqual(0, len(bmsgs))

    def test_ModeratorStore(self):
        moderators = self.moderators.get_moderator(self.u.guid)
        self.assertIsNone(moderators)

        self.moderators.save_moderator(self.u.guid,
                                       self.u.pubkey, '', '', '', 'JOHN', '', '0', '')
        moderators = self.moderators.get_moderator(self.u.guid)
        self.assertEqual(moderators[0], self.u.guid)

        self.moderators.delete_moderator(self.u.guid)
        moderators = self.moderators.get_moderator(self.u.guid)
        self.assertIsNone(moderators)

        self.moderators.save_moderator(self.u.guid,
                                       self.u.pubkey, '', '', '', 'JOHN', '', '0', '')
        self.moderators.clear_all()
        moderators = self.moderators.get_moderator(self.u.guid)
        self.assertIsNone(moderators)

    def test_Purchases(self):
        purchase = self.purchases.get_purchase('NO_EXIST')
        self.assertIsNone(purchase)
        purchases = self.purchases.get_all()
        self.assertEqual(0, len(purchases))

        self.purchases.new_purchase('OID', 'NEW', '', ZERO_TIMESTAMP, '', '', '0', '', '', '', '')
        purchase = self.purchases.get_purchase('OID')
        self.assertEqual('OID', purchase[0])
        purchases = self.purchases.get_all()
        self.assertEqual(1, len(purchases))

        unfunded = self.purchases.get_unfunded()
        self.assertEqual(1, len(unfunded))

        status = self.purchases.get_status('OID')
        self.assertEqual(0, status)

        self.purchases.update_status('OID', 1)
        status = self.purchases.get_status('OID')
        self.assertEqual(1, status)

        unfunded = self.purchases.get_unfunded()
        self.assertEqual(0, len(unfunded))

        outpoint = self.purchases.get_outpoint('OID')
        self.assertIsNone(outpoint)
        self.purchases.update_outpoint('OID', 'OUTPOINT')
        outpoint = self.purchases.get_outpoint('OID')
        self.assertEqual('OUTPOINT', outpoint)

        self.purchases.delete_purchase('OID')
        purchase = self.purchases.get_purchase('OID')
        self.assertIsNone(purchase)

    def test_Sales(self):
        sale = self.sales.get_sale('NO_EXIST')
        self.assertIsNone(sale)
        sales = self.sales.get_all()
        self.assertEqual(0, len(sales))

        self.sales.new_sale('OID', 'NEW', '', ZERO_TIMESTAMP, '', '', '0', '', '', '')
        sale = self.sales.get_sale('OID')
        self.assertEqual('OID', sale[0])
        sales = self.sales.get_all()
        self.assertEqual(1, len(sales))

        unfunded = self.sales.get_unfunded()
        self.assertEqual(1, len(unfunded))

        status = self.sales.get_status('OID')
        self.assertEqual(0, status)

        self.sales.update_status('OID', 1)
        status = self.sales.get_status('OID')
        self.assertEqual(1, status)

        unfunded = self.sales.get_unfunded()
        self.assertEqual(0, len(unfunded))

        outpoint = self.sales.get_outpoint('OID')
        self.assertIsNone(outpoint)
        self.sales.update_outpoint('OID', 'OUTPOINT')
        outpoint = self.sales.get_outpoint('OID')
        self.assertEqual('OUTPOINT', outpoint)

        self.sales.update_payment_tx('OID', 'TXDI')
        # no get method for payment_tx

        self.sales.delete_sale('OID')
        sale = self.sales.get_sale('OID')
        self.assertIsNone(sale)

    def test_NotificationStore(self):
        n = self.ns.get_notifications("1234", 20)
        self.assertTrue(len(n) == 0)
        self.ns.save_notification("1234", self.u.guid, self.m.handle, 'NOTICE', "", ""
                                  '0000-00-00 00:00:00', '', 0)
        n = self.ns.get_notifications("1234", 20)
        self.assertIsNotNone(n)
        self.ns.mark_as_read("1234")

        self.ns.delete_notification("1234")
        n = self.ns.get_notifications("1234", 20)
        self.assertTrue(len(n) == 0)

    def test_VendorStore(self):
        v = self.vs.get_vendors()
        self.assertEqual(v, {})
        addr = Node.IPAddress()
        addr.ip = "127.0.0.1"
        addr.port = 1234
        n = Node()
        n.guid = digest("abcdefg")
        n.publicKey = digest("signed pubkey")
        n.nodeAddress.MergeFrom(addr)
        n.natType = FULL_CONE
        self.vs.save_vendor(self.u.guid, n.SerializeToString())
        v = self.vs.get_vendors()
        self.assertIsNot(v, {})
        self.vs.delete_vendor(self.u.guid)
        v = self.vs.get_vendors()
        self.assertEqual(v, {})

    def test_Settings(self):
        NUM_SETTINGS = 14
        settings = self.settings.get()
        self.assertIsNone(settings)

        self.settings.update('NEW_ADDRESS', 'BTC', 'AUSTRALIA', 'EN',
                             '', '', '', '', '', '', '')
        settings = self.settings.get()
        self.assertEqual(NUM_SETTINGS, len(settings))




