import unittest
import os
from db import datastore
from protos.objects import Profile, Listings
from protos.countries import CountryCode


class DatastoreTest(unittest.TestCase):
    def setUp(self):
        datastore.create_database("test.db")
        datastore.DATABASE = "test.db"
        self.test_hash = "87e0555568bf5c7e4debd6645fc3f41e88df6ca8"
        self.test_hash2 = "97e0555568bf5c7e4debd6645fc3f41e88df6ca8"
        self.test_file = "Contents of test.txt"
        self.test_file2 = "Contents of test2.txt"

        self.sp = Profile()
        self.sp.name = "Test User"
        self.sp.encryption_key = "Key"
        self.sp.location = CountryCode.Value('UNITED_STATES')

        self.serialized_listings = Listings()
        self.lm = self.serialized_listings.ListingMetadata()
        self.lm.contract_hash = self.test_hash
        self.lm.title = "TEST CONTRACT TITLE"
        self.lm.price = 0
        self.lm.currency_code = "USD"
        self.lm.nsfw = False
        self.lm.origin = CountryCode.Value('ALL')

        self.hm = datastore.HashMap()
        self.hm.delete_all()

        self.ps = datastore.ProfileStore()
        self.ls = datastore.ListingsStore()
        self.ks = datastore.KeyStore()

    def tearDown(self):
        os.remove("test.db")

    def test_hashmapInsert(self):
        self.hm.insert(self.test_hash, self.test_file)
        f = self.hm.get_file(self.test_hash)

        self.assertEqual(f, self.test_file)

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
        l = self.ls.get_proto()
        val = Listings()
        val.ParseFromString(l)
        self.assertEqual(self.lm, val.listing[0])

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
