__author__ = 'chris'

import json
import re
import os
from binascii import unhexlify, hexlify
from protos.objects import Listings
from protos.countries import CountryCode
from dht.utils import digest
from constants import DATA_FOLDER
from db.datastore import HashMap, ListingsStore
from collections import OrderedDict
from market.profile import Profile

class Contract(object):
    """
    A class for creating and interacting with OpenBazaar Ricardian contracts.
    """
    def __init__(self, contract=None, hash=None):
        """
        This class can be instantiated with either an `OrderedDict` or a hash
        of a contract. If a hash is used, we will load the contract from either
        the file system or cache.

        Alternatively, pass in no parameters if the intent is to create a new
        contract.

        Args:
            contract: an `OrderedDict` containing a filled out json contract
            hash: a hash (in raw bytes) of a contract
        """
        if contract is not None:
            self.contract = contract
        elif hash is not None:
            try:
                file_path = HashMap().get_file(hash)
                if file_path is None:
                    file_path = DATA_FOLDER + "cache/" + hexlify(hash)
                with open(file_path, 'r') as file:
                    self.contract = json.load(file, object_pairs_hook=OrderedDict)
            except:
                self.contract = {}
        else:
            self.contract = {}

    def create(self,
               expiration_date,
               metadata_category,
               title,
               description,
               currency_code,
               price,
               process_time,
               nsfw,
               est_delivery_domestic=None,
               est_delivery_international=None,
               shipping_origin=None,
               shipping_regions=None,
               keywords=None,
               category=None,
               condition=None,
               sku=None,
               images=None,
               free_shipping=None,
               shipping_currency_code=None,
               shipping_domestic=None,
               shipping_international=None):
        """
        All parameters are strings except:

        :param expiration_date: `string` (must be formatted UTC datetime)
        :param keywords: `list`
        :param nsfw: `boolean`
        :param images: a `list` of image files
        :param free_shipping: `boolean`
        :param shipping_origin: a 'string' formatted `CountryCode`
        :param shipping_regions: a 'list' of 'string' formatted `CountryCode`s
        """

        # TODO: import keys into the contract, import moderator information from db, sign contract.
        profile = Profile().get()

        self.contract = OrderedDict(
            {
                "vendor_offer": {
                    "listing": {
                        "metadata": {
                            "version": "0.1",
                            "expiry": expiration_date + " UTC",
                            "category": metadata_category,
                            "category_sub": "fixed price"
                        },
                        "id": {
                            "guid": "72553255c43f46dbfada66c6b108a991102f4bb9",
                            "pubkeys": {
                                "guid": "5bf3efa2ba168c3e627884349fff1a94723bdfa9f17cc471dff5b628165f60ce",
                                "bitcoin": "16bed6368b8b1542cd6eb87f5bc20dc830b41a2258dde40438a75fa701d24e9a"
                            }
                        },
                        "item": {
                            "title": title,
                            "description": description,
                            "process_time": process_time,
                            "price_per_unit": {},
                            "nsfw": nsfw
                        }
                    }
                }
            }
        )
        if metadata_category == "physical good" and condition is not None:
            self.contract["vendor_offer"]["listing"]["item"]["condition"] = condition
        if currency_code.upper() == "BTC":
            self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["bitcoin"] = price
        else:
            self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["price"] = price
            self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["currency_code"] = currency_code
        if keywords is not None:
            self.contract["vendor_offer"]["listing"]["item"]["keywords"] = []
            self.contract["vendor_offer"]["listing"]["item"]["keywords"].extend(keywords)
        if category is not None:
            self.contract["vendor_offer"]["listing"]["item"]["category"] = category
        if sku is not None:
            self.contract["vendor_offer"]["listing"]["item"]["sku"] = sku
        if metadata_category == "physical good":
            self.contract["vendor_offer"]["listing"]["shipping"] = {}
            self.contract["vendor_offer"]["listing"]["shipping"]["shipping_origin"] = shipping_origin
            if free_shipping is False:
                self.contract["vendor_offer"]["listing"]["shipping"]["free"] = False
                self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"] = {}
                if shipping_currency_code == "BTC":
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["domestic"] = shipping_domestic
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["international"] = shipping_international
                else:
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["domestic"] = shipping_domestic
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["international"] = shipping_international
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["currency_code"] = shipping_currency_code
            else:
                self.contract["vendor_offer"]["listing"]["shipping"]["free"] = True
            self.contract["vendor_offer"]["listing"]["shipping"]["shipping_regions"] = []
            for region in shipping_regions:
                self.contract["vendor_offer"]["listing"]["shipping"]["shipping_regions"].append(region)
            self.contract["vendor_offer"]["listing"]["shipping"]["est_delivery"] = {}
            self.contract["vendor_offer"]["listing"]["shipping"]["est_delivery"]["domestic"] = est_delivery_domestic
            self.contract["vendor_offer"]["listing"]["shipping"]["est_delivery"]["international"] = est_delivery_international
        if profile.HasField("handle"):
            self.contract["vendor_offer"]["listing"]["id"]["blockchain_id"] = profile.handle
        if images is not None:
            self.contract["vendor_offer"]["listing"]["item"]["image_hashes"] = []
            for image in images:
                hash = digest(image).encode("hex")
                self.contract["vendor_offer"]["listing"]["item"]["image_hashes"].append(hash)
                with open(DATA_FOLDER + "store/media/" + hash, 'w') as outfile:
                    outfile.write(image)
                HashMap().insert(digest(image), DATA_FOLDER + "store/media/" + hash)
        self.save()

    def update(self,
               expiration_date=None,
               metadata_category=None,
               title=None,
               description=None,
               currency_code=None,
               price=None,
               process_time=None,
               nsfw=None,
               est_delivery_domestic=None,
               est_delivery_international=None,
               shipping_origin=None,
               shipping_regions=None,
               keywords=None,
               category=None,
               condition=None,
               sku=None,
               image_hashes=None,  # if intending to delete an image, pass in the hashes that are staying.
               images=None,  # to add new images pass in a list of image files.
               free_shipping=None,
               shipping_currency_code=None,
               shipping_domestic=None,
               shipping_international=None):

        self.delete(False)
        if expiration_date is not None:
            self.contract["vendor_offer"]["listing"]["item"]["expiry"] = expiration_date
        if metadata_category is not None:
            if metadata_category != "physical good" and self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "physical good":
                del self.contract["vendor_offer"]["listing"]["shipping"]
            elif metadata_category == "physical good" and self.contract["vendor_offer"]["listing"]["metadata"]["category"] != "physical good":
                self.contract["vendor_offer"]["listing"]["shipping"] = {}
                self.contract["vendor_offer"]["listing"]["shipping"]["est_delivery"] = {}
                self.contract["vendor_offer"]["listing"]["shipping"]["free"] = False
            self.contract["vendor_offer"]["listing"]["metadata"]["category"] = metadata_category
        if title is not None:
            self.contract["vendor_offer"]["listing"]["item"]["title"] = title
        if description is not None:
            self.contract["vendor_offer"]["listing"]["item"]["description"] = description
        if currency_code is not None:
            if currency_code.upper() != "BTC" and "bitcoin" in self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]:
                p = self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["bitcoin"]
                del self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["bitcoin"]
                self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"] = {}
                self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["currency_code"] = currency_code
                self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["price"] = p
            elif currency_code.upper() == "BTC" and "fiat" in self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]:
                p = self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["price"]
                del self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]
                self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["bitcoin"] = p
        if price is not None:
            if "bitcoin" in self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]:
                self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["bitcoin"] = price
            else:
                self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["price"] = price
        if process_time is not None:
            self.contract["vendor_offer"]["listing"]["item"]["process_time"] = process_time
        if nsfw is not None:
            self.contract["vendor_offer"]["listing"]["item"]["nsfw"] = nsfw
        if keywords is not None:
            self.contract["vendor_offer"]["listing"]["item"]["keywords"] = []
            self.contract["vendor_offer"]["listing"]["item"]["keywords"].extend(keywords)
        if category is not None:
            self.contract["vendor_offer"]["listing"]["item"]["category"] = category
        if image_hashes is not None:
            to_delete = list(set(self.contract["vendor_offer"]["listing"]["item"]["image_hashes"]) - set(image_hashes))
            for image_hash in to_delete:
                # delete from disk
                h = HashMap()
                image_path = h.get_file(unhexlify(image_hash))
                if os.path.exists(image_path):
                    os.remove(image_path)
                # remove pointer to the image from the HashMap
                h.delete(unhexlify(image_hash))
            self.contract["vendor_offer"]["listing"]["item"]["image_hashes"] = []
            self.contract["vendor_offer"]["listing"]["item"]["image_hashes"].extend(image_hashes)
        if images is not None:
            if "image_hashes" not in self.contract["vendor_offer"]["listing"]["item"]:
                self.contract["vendor_offer"]["listing"]["item"]["image_hashes"] = []
            for image in images:
                hash = digest(image).encode("hex")
                self.contract["vendor_offer"]["listing"]["item"]["image_hashes"].append(hash)
                with open(DATA_FOLDER + "store/media/" + hash, 'w') as outfile:
                    outfile.write(image)
                HashMap().insert(digest(image), DATA_FOLDER + "store/media/" + hash)
        if self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "physical good" and condition is not None:
            self.contract["vendor_offer"]["listing"]["item"]["condition"] = condition
        if sku is not None:
            self.contract["vendor_offer"]["listing"]["item"]["sku"] = sku
        if self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "physical good":
            if shipping_origin is not None:
                self.contract["vendor_offer"]["listing"]["shipping"]["shipping_origin"] = shipping_origin
            if free_shipping is not None:
                if free_shipping is True and self.contract["vendor_offer"]["listing"]["shipping"]["free"] == False:
                    self.contract["vendor_offer"]["listing"]["shipping"]["free"] = True
                    del self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]
                elif free_shipping is False and self.contract["vendor_offer"]["listing"]["shipping"]["free"] == True:
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["free"] = False
            if shipping_currency_code is not None and self.contract["vendor_offer"]["listing"]["shipping"]["free"] == False:
                if shipping_currency_code == "BTC" and "bitcoin" not in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"] = {}
                    d = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["domestic"]
                    i = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["international"]
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["domestic"] = d
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["international"] = i
                    del self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]
                elif shipping_currency_code != "BTC" and "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                    d = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["domestic"]
                    i = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["international"]
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["domestic"] = d
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["international"] = i
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["currency_code"] = shipping_currency_code
                    del self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]
            if shipping_domestic is not None and "bitcoin" not in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["domestic"] = shipping_domestic
            if shipping_international is not None and "bitcoin" not in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"]["price"]["international"] = shipping_international
            if shipping_domestic is not None and "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["domestic"] = shipping_domestic
            if shipping_international is not None and "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"]["international"] = shipping_international
            if shipping_regions is not None:
                self.contract["vendor_offer"]["listing"]["shipping"]["shipping_regions"] = shipping_regions
            if est_delivery_domestic is not None:
                self.contract["vendor_offer"]["listing"]["shipping"]["est_delivery"]["domestic"] = est_delivery_domestic
            if est_delivery_international is not None:
                self.contract["vendor_offer"]["listing"]["shipping"]["est_delivery"]["international"] = est_delivery_international

        self.save()

    def delete(self, delete_images=True):
        """
        Deletes the contract json from the OpenBazaar directory as well as the listing
        metadata from the db and all the related images in the file system.
        """
        # build the file_name from the contract
        file_name = str(self.contract["vendor_offer"]["listing"]["item"]["title"][:100])
        file_name = re.sub(r"[^\w\s]", '', file_name)
        file_name = re.sub(r"\s+", '_', file_name)
        file_path = DATA_FOLDER + "store/listings/contracts/" + file_name + ".json"

        h = HashMap()

        # maybe delete the images from disk
        if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"] and delete_images:
            for image_hash in self.contract["vendor_offer"]["listing"]["item"]["image_hashes"]:
                # delete from disk
                image_path = h.get_file(unhexlify(image_hash))
                if os.path.exists(image_path):
                    os.remove(image_path)
                # remove pointer to the image from the HashMap
                h.delete(unhexlify(image_hash))

        # delete the contract from disk
        if os.path.exists(file_path):
            os.remove(file_path)
        # delete the listing metadata from the db
        contract_hash = digest(json.dumps(self.contract, indent=4))
        ListingsStore().delete_listing(contract_hash)
        # remove the pointer to the contract from the HashMap
        h.delete(contract_hash)

    def save(self):
        """
        Saves the json contract into the OpenBazaar/store/listings/contracts/ directory.
        It uses the title as the file name so it's easy on human eyes. A mapping of the
        hash of the contract and file path is stored in the database so we can retrieve
        the contract with only its hash.

        Additionally, the contract metadata (sent in response to the GET_LISTINGS query)
        is saved in the db for fast access.
        """
        # get the contract title to use as the file name and format it
        file_name = str(self.contract["vendor_offer"]["listing"]["item"]["title"][:100])
        file_name = re.sub(r"[^\w\s]", '', file_name)
        file_name = re.sub(r"\s+", '_', file_name)

        # save the json contract to the file system
        file_path = DATA_FOLDER + "store/listings/contracts/" + file_name + ".json"
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))

        # Create a `ListingMetadata` protobuf object using data from the full contract
        listings = Listings()
        data = listings.ListingMetadata()
        data.contract_hash = digest(json.dumps(self.contract, indent=4))
        data.title = self.contract["vendor_offer"]["listing"]["item"]["title"]
        if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"]:
            data.thumbnail_hash = unhexlify(self.contract["vendor_offer"]["listing"]["item"]["image_hashes"][0])
        data.category = self.contract["vendor_offer"]["listing"]["item"]["category"]
        if "bitcoin" not in self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]:
            data.price = float(self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["price"])
            data.currency_code = self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["currency_code"]
        else:
            data.price = float(self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["bitcoin"])
            data.currency_code = "BTC"
        data.nsfw = self.contract["vendor_offer"]["listing"]["item"]["nsfw"]
        if "shipping" not in self.contract["vendor_offer"]["listing"]:
            data.origin = CountryCode.Value("NA")
        else:
            data.origin = CountryCode.Value(self.contract["vendor_offer"]["listing"]["shipping"]["shipping_origin"].upper())
            for region in self.contract["vendor_offer"]["listing"]["shipping"]["shipping_regions"]:
                data.ships_to.append(CountryCode.Value(region.upper()))

        # save the mapping of the contract file path and contract hash in the database
        HashMap().insert(data.contract_hash, file_path)

        # save the `ListingMetadata` protobuf to the database as well
        ListingsStore().add_listing(data)