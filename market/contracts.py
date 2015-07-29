__author__ = 'chris'

import json
import re

from binascii import unhexlify

from protos.objects import Listings

from dht.utils import digest

from constants import DATA_FOLDER

from db.datastore import HashMap, ListingsStore

"""
A full contract class will be built around this
"""

def store_contract(contract):
    """
    Saves the json contract into the OpenBazaar/store/listings/contracts/ directory.
    It uses the title as the file name so it's easy on human eyes. A mapping of the
    hash of the contract and file path is stored in the database so we can retrieve
    the contract with only its hash.

    Additionally, the contract metadata (sent in response to the GET_LISTINGS query)
    is saved in the db for fast access.

    Args:
        contract: a `json` object containing the fully filled out and signed ricardian
                contract.
    """
    # get the contract title to use as the file name and format it
    file_name = str(contract["vendor"]["listing"]["item"]["title"][:100])
    file_name = re.sub(r"[^\w\s]", '', file_name)
    file_name = re.sub(r"\s+", '_', file_name)

    # save the json contract to the file system
    file_path = DATA_FOLDER + "store/listings/contracts/" + file_name + ".json"
    with open(file_path, 'w') as outfile:
        outfile.write(json.dumps(contract, indent=4))

    # Create a `ListingMetadata` protobuf object using data from the full contract
    listings = Listings()
    data = listings.ListingMetadata()
    data.contract_hash = digest(json.dumps(contract, indent=4))
    data.title = contract["vendor"]["listing"]["item"]["title"]
    data.thumbnail_hash = unhexlify(contract["vendor"]["listing"]["item"]["images"]["image_hashes"][0])
    data.category = contract["vendor"]["listing"]["item"]["category"]
    if "bitcoin" not in contract["vendor"]["listing"]["item"]["price"]:
        data.price = float(contract["vendor"]["listing"]["item"]["price"]["fiat"]["price"])
        data.currency_code = contract["vendor"]["listing"]["item"]["price"]["fiat"]["currency_code"]
    else:
        data.price = float(contract["vendor"]["listing"]["item"]["price"]["bitcoin"])
        data.currency_code = "btc"

    # save the mapping of the contract file path and contract hash in the database
    h = HashMap()
    h.insert(data.contract_hash, file_path)

    # save the `ListingMetadata` protobuf to the database as well
    l = ListingsStore()
    l.add_listing(data)