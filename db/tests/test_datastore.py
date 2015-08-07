import unittest
from db import datastore
from protos.objects import Profile, Listings
from protos.countries import CountryCode


class DatastoreTest(unittest.TestCase):

    def setUp(self):
        self.test_hash = "87e0555568bf5c7e4debd6645fc3f41e88df6ca8"
        self.test_hash2 = "97e0555568bf5c7e4debd6645fc3f41e88df6ca8"
        self.test_file = "Contents of test.txt"
        self.test_file2 = "Contents of test2.txt"
        self.serialized_profile = Profile()

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
        self.ps.set_proto(self.serialized_profile)
        sp = self.ps.get_proto()
        self.assertEqual(self.serialized_profile, sp)

    def test_addListing(self):
        self.ls.delete_all_listings()
        self.ls.add_listing(self.lm)
        l = self.ls.get_proto()
        s = self.lm.SerializeToString()
        self.assertEqual(s, l)
