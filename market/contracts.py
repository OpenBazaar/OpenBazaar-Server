__author__ = 'chris'

import json
import random
import time
import pickle
import nacl.signing
import bitcoin
from hashlib import sha256
from binascii import unhexlify, hexlify
from collections import OrderedDict
from urllib2 import Request, urlopen, URLError
from market.utils import deserialize

import re
import os
import nacl.encoding
from protos.objects import Listings
from protos.countries import CountryCode
from dht.utils import digest
from constants import DATA_FOLDER
from market.profile import Profile
from keyutils.keys import KeyChain
from keyutils.bip32utils import derive_childkey
from log import Logger
from constants import TRANSACTION_FEE


class Contract(object):
    """
    A class for creating and interacting with OpenBazaar Ricardian contracts.
    """

    def __init__(self, database, contract=None, hash_value=None, testnet=False):
        """
        This class can be instantiated with either an `OrderedDict` or a hash
        of a contract. If a hash is used, we will load the contract from either
        the file system or cache.

        Alternatively, pass in no parameters if the intent is to create a new
        contract.

        Args:
            contract: an `OrderedDict` containing a filled out json contract
            hash_value: a hash160 (in hex) of a contract
            testnet: is this contract on the testnet
        """
        self.db = database
        self.keychain = KeyChain(self.db)
        if contract is not None:
            self.contract = contract
        elif hash_value is not None:
            try:
                file_path = self.db.HashMap().get_file(hash_value)
                if file_path is None:
                    file_path = DATA_FOLDER + "cache/" + hexlify(hash_value)
                with open(file_path, 'r') as filename:
                    self.contract = json.load(filename, object_pairs_hook=OrderedDict)
            except Exception:
                try:
                    file_path = DATA_FOLDER + "purchases/in progress/" + hexlify(hash_value) + ".json"
                    with open(file_path, 'r') as filename:
                        self.contract = json.load(filename, object_pairs_hook=OrderedDict)
                except Exception:
                    self.contract = {}
        else:
            self.contract = {}
        self.log = Logger(system=self)

        # used when purchasing this contract
        self.testnet = testnet
        self.notification_listener = None
        self.blockchain = None
        self.amount_funded = 0
        self.received_txs = []
        self.is_purchase = False
        self.outpoints = []

    def create(self,
               expiration_date,
               metadata_category,
               title,
               description,
               currency_code,
               price,
               process_time,
               nsfw,
               shipping_origin=None,
               shipping_regions=None,
               est_delivery_domestic=None,
               est_delivery_international=None,
               terms_conditions=None,
               returns=None,
               keywords=None,
               category=None,
               condition=None,
               sku=None,
               images=None,
               free_shipping=None,
               shipping_currency_code=None,
               shipping_domestic=None,
               shipping_international=None,
               options=None,
               moderators=None):
        """
        All parameters are strings except:

        :param expiration_date: `string` (must be formatted UTC datetime)
        :param keywords: `list`
        :param nsfw: `boolean`
        :param images: a `list` of image files
        :param free_shipping: `boolean`
        :param shipping_origin: a 'string' formatted `CountryCode`
        :param shipping_regions: a 'list' of 'string' formatted `CountryCode`s
        :param options: a 'dict' containing options as keys and 'list' as option values.
        :param moderators: a 'list' of 'string' guids (hex encoded).
        """

        profile = Profile(self.db).get()
        self.contract = OrderedDict(
            {
                "vendor_offer": {
                    "listing": {
                        "metadata": {
                            "version": "0.1",
                            "category": metadata_category.lower(),
                            "category_sub": "fixed price"
                        },
                        "id": {
                            "guid": self.keychain.guid.encode("hex"),
                            "pubkeys": {
                                "guid": self.keychain.guid_signed_pubkey[64:].encode("hex"),
                                "bitcoin": bitcoin.bip32_extract_key(self.keychain.bitcoin_master_pubkey),
                                "encryption": self.keychain.encryption_pubkey.encode("hex")
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
        if expiration_date == "":
            self.contract["vendor_offer"]["listing"]["metadata"]["expiry"] = "never"
        else:
            self.contract["vendor_offer"]["listing"]["metadata"]["expiry"] = expiration_date + " UTC"
        if metadata_category == "physical good" and condition is not None:
            self.contract["vendor_offer"]["listing"]["item"]["condition"] = condition
        if currency_code.upper() == "BTC":
            item = self.contract["vendor_offer"]["listing"]["item"]
            item["price_per_unit"]["bitcoin"] = round(float(price), 8)
        else:
            item = self.contract["vendor_offer"]["listing"]["item"]
            item["price_per_unit"]["fiat"] = {}
            item["price_per_unit"]["fiat"]["price"] = price
            item["price_per_unit"]["fiat"]["currency_code"] = currency_code
        if keywords is not None:
            self.contract["vendor_offer"]["listing"]["item"]["keywords"] = []
            self.contract["vendor_offer"]["listing"]["item"]["keywords"].extend(keywords)
        if category is not None:
            self.contract["vendor_offer"]["listing"]["item"]["category"] = category
        if sku is not None:
            self.contract["vendor_offer"]["listing"]["item"]["sku"] = sku
        if options is not None:
            self.contract["vendor_offer"]["listing"]["item"]["options"] = options
        if metadata_category == "physical good":
            self.contract["vendor_offer"]["listing"]["shipping"] = {}
            shipping = self.contract["vendor_offer"]["listing"]["shipping"]
            shipping["shipping_origin"] = shipping_origin
            if free_shipping is False:
                self.contract["vendor_offer"]["listing"]["shipping"]["free"] = False
                self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"] = {}
                if shipping_currency_code == "BTC":
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"] = {}
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"][
                        "domestic"] = shipping_domestic
                    self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["bitcoin"][
                        "international"] = shipping_international
                else:
                    shipping = self.contract["vendor_offer"]["listing"]["shipping"]
                    shipping["flat_fee"]["fiat"] = {}
                    shipping["flat_fee"]["fiat"]["price"] = {}
                    shipping["flat_fee"]["fiat"]["price"][
                        "domestic"] = shipping_domestic
                    shipping["flat_fee"]["fiat"]["price"][
                        "international"] = shipping_international
                    shipping["flat_fee"]["fiat"][
                        "currency_code"] = shipping_currency_code
            else:
                self.contract["vendor_offer"]["listing"]["shipping"]["free"] = True
            self.contract["vendor_offer"]["listing"]["shipping"]["shipping_regions"] = []
            for region in shipping_regions:
                shipping = self.contract["vendor_offer"]["listing"]["shipping"]
                shipping["shipping_regions"].append(region)
            listing = self.contract["vendor_offer"]["listing"]
            listing["shipping"]["est_delivery"] = {}
            listing["shipping"]["est_delivery"]["domestic"] = est_delivery_domestic
            listing["shipping"]["est_delivery"][
                "international"] = est_delivery_international
        if profile.HasField("handle"):
            self.contract["vendor_offer"]["listing"]["id"]["blockchain_id"] = profile.handle
        if images is not None:
            self.contract["vendor_offer"]["listing"]["item"]["image_hashes"] = []
            for image_hash in images:
                if len(image_hash) != 40:
                    raise Exception("Invalid image hash")
                self.contract["vendor_offer"]["listing"]["item"]["image_hashes"].append(image_hash)
        if terms_conditions is not None or returns is not None:
            self.contract["vendor_offer"]["listing"]["policy"] = {}
            if terms_conditions is not None:
                self.contract["vendor_offer"]["listing"]["policy"]["terms_conditions"] = terms_conditions
            if returns is not None:
                self.contract["vendor_offer"]["listing"]["policy"]["returns"] = returns
        if moderators is not None:
            self.contract["vendor_offer"]["listing"]["moderators"] = []
            for mod in moderators:
                mod_info = self.db.ModeratorStore().get_moderator(mod)
                if mod_info is not None:
                    moderator = {
                        "guid": mod,
                        "name": mod_info[7],
                        "avatar": mod_info[9].encode("hex"),
                        "short_description": mod_info[8],
                        "fee": str(mod_info[10]) + "%",
                        "blockchain_id": mod_info[6],
                        "pubkeys": {
                            "signing": {
                                "key": mod_info[1][64:].encode("hex"),
                                "signature": mod_info[1][:64].encode("hex")
                            },
                            "encryption": {
                                "key": mod_info[2].encode("hex"),
                                "signature": mod_info[3].encode("hex")
                            },
                            "bitcoin": {
                                "key": mod_info[4].encode("hex"),
                                "signature": mod_info[5].encode("hex")
                            }
                        }
                    }
                    self.contract["vendor_offer"]["listing"]["moderators"].append(moderator)

        listing = json.dumps(self.contract["vendor_offer"]["listing"], indent=4)
        self.contract["vendor_offer"]["signature"] = \
            self.keychain.signing_key.sign(listing, encoder=nacl.encoding.HexEncoder)[:128]
        self.save()

    def add_purchase_info(self,
                          quantity,
                          ship_to=None,
                          shipping_address=None,
                          city=None,
                          state=None,
                          postal_code=None,
                          country=None,
                          moderator=None,
                          options=None):
        """
        Update the contract with the buyer's purchase information.
        """

        profile = Profile(self.db).get()
        order_json = {
            "buyer_order": {
                "order": {
                    "ref_hash": digest(json.dumps(self.contract, indent=4)).encode("hex"),
                    "quantity": quantity,
                    "id": {
                        "guid": self.keychain.guid.encode("hex"),
                        "pubkeys": {
                            "guid": self.keychain.guid_signed_pubkey[64:].encode("hex"),
                            "bitcoin": bitcoin.bip32_extract_key(self.keychain.bitcoin_master_pubkey),
                            "encryption": self.keychain.encryption_pubkey.encode("hex")
                        }
                    },
                    "payment": {}
                }
            }
        }
        if profile.HasField("handle"):
            order_json["buyer_order"]["order"]["id"]["blockchain_id"] = profile.handle
        if self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "physical good":
            order_json["buyer_order"]["order"]["shipping"] = {}
            order_json["buyer_order"]["order"]["shipping"]["ship_to"] = ship_to
            order_json["buyer_order"]["order"]["shipping"]["address"] = shipping_address
            order_json["buyer_order"]["order"]["shipping"]["city"] = city
            order_json["buyer_order"]["order"]["shipping"]["state"] = state
            order_json["buyer_order"]["order"]["shipping"]["postal_code"] = postal_code
            order_json["buyer_order"]["order"]["shipping"]["country"] = country
        if options is not None:
            order_json["buyer_order"]["order"]["options"] = options
        if moderator:
            chaincode = sha256(str(random.getrandbits(256))).digest().encode("hex")
            order_json["buyer_order"]["order"]["payment"]["chaincode"] = chaincode
            valid_mod = False
            for mod in self.contract["vendor_offer"]["listing"]["moderators"]:
                if mod["guid"] == moderator:
                    order_json["buyer_order"]["order"]["moderator"] = moderator
                    masterkey_m = mod["pubkeys"]["bitcoin"]["key"]
                    valid_mod = True
            if not valid_mod:
                return False
            masterkey_b = bitcoin.bip32_extract_key(self.keychain.bitcoin_master_pubkey)
            masterkey_v = self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
            buyer_key = derive_childkey(masterkey_b, chaincode)
            vendor_key = derive_childkey(masterkey_v, chaincode)
            moderator_key = derive_childkey(masterkey_m, chaincode)

            redeem_script = bitcoin.mk_multisig_script([buyer_key, vendor_key, moderator_key], 2)
            order_json["buyer_order"]["order"]["payment"]["redeem_script"] = redeem_script
            if self.testnet:
                payment_address = bitcoin.p2sh_scriptaddr(redeem_script, 196)
            else:
                payment_address = bitcoin.p2sh_scriptaddr(redeem_script)
            order_json["buyer_order"]["order"]["payment"]["address"] = payment_address
        else:
            chaincode = sha256(str(random.getrandbits(256))).digest().encode("hex")
            order_json["buyer_order"]["order"]["payment"]["chaincode"] = chaincode

            masterkey_v = self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
            vendor_key = derive_childkey(masterkey_v, chaincode)

            if self.testnet:
                payment_address = bitcoin.pubkey_to_address(vendor_key, 111)
            else:
                payment_address = bitcoin.pubkey_to_address(vendor_key)
            order_json["buyer_order"]["order"]["payment"]["address"] = payment_address

        price_json = self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]
        if "bitcoin" in price_json:
            amount_to_pay = float(price_json["bitcoin"]) * quantity
        else:
            currency_code = price_json["fiat"]["currency_code"]
            fiat_price = price_json["fiat"]["price"]
            try:
                request = Request('https://api.bitcoinaverage.com/ticker/' + currency_code.upper() + '/last')
                response = urlopen(request)
                conversion_rate = response.read()
            except URLError:
                return False
            amount_to_pay = float("{0:.8f}".format(float(fiat_price) / float(conversion_rate))) * quantity
        if "shipping" in self.contract["vendor_offer"]["listing"]:
            if not self.contract["vendor_offer"]["listing"]["shipping"]["free"]:
                shipping_origin = str(self.contract["vendor_offer"]["listing"]["shipping"][
                    "shipping_origin"].upper())
                if shipping_origin == country.upper():
                    if "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                        shipping_amount = float(self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                            "bitcoin"]["domestic"]) * quantity
                    else:
                        price = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"][
                            "price"]["domestic"]
                        currency = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                            "fiat"]["currency_code"]
                        try:
                            request = Request('https://api.bitcoinaverage.com/ticker/' + currency.upper() + '/last')
                            response = urlopen(request)
                            conversion_rate = response.read()
                        except URLError:
                            return False
                        shipping_amount = round(
                            float("{0:.8f}".format(float(price) / float(conversion_rate))) * quantity, 8)
                else:
                    if "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                        shipping_amount = float(self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                            "bitcoin"]["international"]) * quantity
                    else:
                        price = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"][
                            "price"]["international"]
                        currency = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                            "fiat"]["currency_code"]
                        try:
                            request = Request('https://api.bitcoinaverage.com/ticker/' + currency.upper() + '/last')
                            response = urlopen(request)
                            conversion_rate = response.read()
                        except URLError:
                            return False
                        shipping_amount = round(
                            float("{0:.8f}".format(float(price) / float(conversion_rate))) * quantity, 8)
                amount_to_pay += shipping_amount

        order_json["buyer_order"]["order"]["payment"]["amount"] = amount_to_pay

        self.contract["buyer_order"] = order_json["buyer_order"]
        order = json.dumps(self.contract["buyer_order"]["order"], indent=4)
        # TODO: This should also be signed with the bitcoin key. It's the only way a moderator
        # will have to link this contract to a bitcoin transaction.
        self.contract["buyer_order"]["signature"] = \
            self.keychain.signing_key.sign(order, encoder=nacl.encoding.HexEncoder)[:128]
        return (self.contract["buyer_order"]["order"]["payment"]["address"],
                order_json["buyer_order"]["order"]["payment"]["amount"])

    def add_order_confirmation(self,
                               libbitcoin_client,
                               payout_address,
                               comments=None,
                               shipper=None,
                               tracking_number=None,
                               est_delivery=None,
                               url=None,
                               password=None):
        """
        Add the vendor's order confirmation to the contract.
        """
        self.blockchain = libbitcoin_client
        if not self.testnet and not (payout_address[:1] == "1" or payout_address[:1] == "3"):
            raise Exception("Bitcoin address is not a mainnet address")
        elif self.testnet and not \
                (payout_address[:1] == "n" or payout_address[:1] == "m" or payout_address[:1] == "2"):
            raise Exception("Bitcoin address is not a testnet address")
        try:
            bitcoin.b58check_to_hex(payout_address)
        except AssertionError:
            raise Exception("Invalid Bitcoin address")
        conf_json = {
            "vendor_order_confirmation": {
                "invoice": {
                    "ref_hash": digest(json.dumps(self.contract, indent=4)).encode("hex")
                }
            }
        }
        if self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "physical good":
            shipping = {"shipper": shipper, "tracking_number": tracking_number, "est_delivery": est_delivery}
            conf_json["vendor_order_confirmation"]["invoice"]["shipping"] = shipping
        elif self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "digital good":
            content_source = {"url": url, "password": password}
            conf_json["vendor_order_confirmation"]["invoice"]["content_source"] = content_source
        if comments:
            conf_json["vendor_order_confirmation"]["invoice"]["comments"] = comments
        order_id = digest(json.dumps(self.contract, indent=4)).encode("hex")
        # apply signatures
        outpoints = pickle.loads(self.db.Sales().get_outpoint(order_id))
        if "moderator" in self.contract["buyer_order"]["order"]:
            redeem_script = self.contract["buyer_order"]["order"]["payment"]["redeem_script"]
            value = 0
            for output in outpoints:
                value += output["value"]
                del output["value"]
            value -= TRANSACTION_FEE
            outs = [{'value': value, 'address': payout_address}]
            tx = bitcoin.mktx(outpoints, outs)
            signatures = []
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_v = bitcoin.bip32_extract_key(self.keychain.bitcoin_master_privkey)
            vendor_priv = derive_childkey(masterkey_v, chaincode, bitcoin.MAINNET_PRIVATE)
            for index in range(0, len(outpoints)):
                sig = bitcoin.multisign(tx, index, redeem_script, vendor_priv)
                signatures.append({"input_index": index, "signature": sig})
            conf_json["vendor_order_confirmation"]["invoice"]["payout"] = {}
            conf_json["vendor_order_confirmation"]["invoice"]["payout"]["address"] = payout_address
            conf_json["vendor_order_confirmation"]["invoice"]["payout"]["value"] = value
            conf_json["vendor_order_confirmation"]["invoice"]["payout"]["signature(s)"] = signatures
        else:
            value = 0
            for output in outpoints:
                value += output["value"]
                del output["value"]
            value -= TRANSACTION_FEE
            outs = [{'value': value, 'address': payout_address}]
            tx = bitcoin.mktx(outpoints, outs)
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_v = bitcoin.bip32_extract_key(self.keychain.bitcoin_master_privkey)
            vendor_priv = derive_childkey(masterkey_v, chaincode, bitcoin.MAINNET_PRIVATE)
            for index in range(0, len(outpoints)):
                tx = bitcoin.sign(tx, index, vendor_priv)
            self.blockchain.broadcast(tx)
            self.db.Sales().update_payment_tx(order_id, bitcoin.txhash(tx))

        confirmation = json.dumps(conf_json["vendor_order_confirmation"]["invoice"], indent=4)
        conf_json["vendor_order_confirmation"]["signature"] = \
            self.keychain.signing_key.sign(confirmation, encoder=nacl.encoding.HexEncoder)[:128]

        self.contract["vendor_order_confirmation"] = conf_json["vendor_order_confirmation"]
        self.db.Sales().update_status(order_id, 2)
        file_path = DATA_FOLDER + "store/listings/in progress/" + order_id + ".json"
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))

    def accept_order_confirmation(self, notification_listener, confirmation_json=None):
        """
        Validate the order confirmation sent over from the seller and update our node accordingly.
        """
        self.notification_listener = notification_listener
        try:
            if confirmation_json:
                self.contract["vendor_order_confirmation"] = json.loads(confirmation_json,
                                                                        object_pairs_hook=OrderedDict)

            contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
            del contract_dict["vendor_order_confirmation"]
            contract_hash = digest(json.dumps(contract_dict, indent=4)).encode("hex")
            ref_hash = self.contract["vendor_order_confirmation"]["invoice"]["ref_hash"]
            if ref_hash != contract_hash:
                raise Exception("Order number doesn't match")
            if self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "physical good":
                shipping = self.contract["vendor_order_confirmation"]["invoice"]["shipping"]
                if "tracking_number" not in shipping or "shipper" not in shipping:
                    raise Exception("No shipping information")

            # TODO: verify signature
            # TODO: verify payout object

            # update the order status in the db
            self.db.Purchases().update_status(contract_hash, 2)
            file_path = DATA_FOLDER + "purchases/in progress/" + contract_hash + ".json"

            # update the contract in the file system
            with open(file_path, 'w') as outfile:
                outfile.write(json.dumps(self.contract, indent=4))
            title = self.contract["vendor_offer"]["listing"]["item"]["title"]
            if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"]:
                image_hash = unhexlify(self.contract["vendor_offer"]["listing"]["item"]["image_hashes"][0])
            else:
                image_hash = ""
            if "blockchain_id" in self.contract["vendor_offer"]["listing"]["id"]:
                handle = self.contract["vendor_offer"]["listing"]["id"]["blockchain_id"]
            else:
                handle = ""
            vendor_guid = self.contract["vendor_offer"]["listing"]["id"]["guid"]
            self.notification_listener.notify(vendor_guid, handle, "order confirmation", contract_hash, title,
                                              image_hash)
            return contract_hash
        except Exception:
            return False

    def add_receipt(self,
                    received,
                    libbitcoin_client,
                    feedback=None,
                    quality=None,
                    description=None,
                    delivery_time=None,
                    customer_service=None,
                    review="",
                    dispute=False,
                    claim=None,
                    payout=True):

        """
        Add the final piece of the contract that appends the review and payout transaction.
        """
        self.blockchain = libbitcoin_client
        receipt_json = {
            "buyer_receipt": {
                "receipt": {
                    "ref_hash": digest(json.dumps(self.contract, indent=4)).encode("hex"),
                    "listing": {
                        "received": received,
                        "listing_hash": self.contract["buyer_order"]["order"]["ref_hash"]
                    },
                    "dispute": {
                        "dispute": dispute
                    }
                }
            }
        }
        if None not in (feedback, quality, description, delivery_time, customer_service):
            receipt_json["buyer_receipt"]["receipt"]["rating"] = {}
            receipt_json["buyer_receipt"]["receipt"]["rating"]["feedback"] = feedback
            receipt_json["buyer_receipt"]["receipt"]["rating"]["quality"] = quality
            receipt_json["buyer_receipt"]["receipt"]["rating"]["description"] = description
            receipt_json["buyer_receipt"]["receipt"]["rating"]["delivery_time"] = delivery_time
            receipt_json["buyer_receipt"]["receipt"]["rating"]["customer_service"] = customer_service
            receipt_json["buyer_receipt"]["receipt"]["rating"]["review"] = review
        order_id = self.contract["vendor_order_confirmation"]["invoice"]["ref_hash"]
        if payout and "moderator" in self.contract["buyer_order"]["order"]:
            outpoints = pickle.loads(self.db.Purchases().get_outpoint(order_id))
            payout_address = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["address"]
            redeem_script = str(self.contract["buyer_order"]["order"]["payment"]["redeem_script"])
            for output in outpoints:
                del output["value"]
            value = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["value"]
            outs = [{'value': value, 'address': payout_address}]
            tx = bitcoin.mktx(outpoints, outs)
            signatures = []
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_b = bitcoin.bip32_extract_key(self.keychain.bitcoin_master_privkey)
            buyer_priv = derive_childkey(masterkey_b, chaincode, bitcoin.MAINNET_PRIVATE)
            masterkey_v = self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
            vendor_key = derive_childkey(masterkey_v, chaincode)
            valid_inputs = 0
            for index in range(0, len(outpoints)):
                sig = bitcoin.multisign(tx, index, redeem_script, buyer_priv)
                signatures.append({"input_index": index, "signature": sig})
                for s in self.contract["vendor_order_confirmation"]["invoice"]["payout"]["signature(s)"]:
                    if s["input_index"] == index:
                        if bitcoin.verify_tx_input(tx, index, redeem_script, s["signature"], vendor_key):
                            tx = bitcoin.apply_multisignatures(tx, index, str(redeem_script),
                                                               sig, str(s["signature"]))
                            valid_inputs += 1
            receipt_json["buyer_receipt"]["receipt"]["payout"] = {}
            if valid_inputs == len(outpoints):
                self.log.info("Broadcasting payout tx %s to network" % bitcoin.txhash(tx))
                self.blockchain.broadcast(tx)
                receipt_json["buyer_receipt"]["receipt"]["payout"]["txid"] = bitcoin.txhash(tx)
            receipt_json["buyer_receipt"]["receipt"]["payout"]["signature(s)"] = signatures
            receipt_json["buyer_receipt"]["receipt"]["payout"]["value"] = value
        if claim:
            receipt_json["buyer_receipt"]["receipt"]["dispute"]["claim"] = claim
        receipt = json.dumps(receipt_json["buyer_receipt"]["receipt"], indent=4)
        receipt_json["buyer_receipt"]["signature"] = \
            self.keychain.signing_key.sign(receipt, encoder=nacl.encoding.HexEncoder)[:128]
        self.contract["buyer_receipt"] = receipt_json["buyer_receipt"]
        self.db.Purchases().update_status(order_id, 3)
        file_path = DATA_FOLDER + "purchases/trade receipts/" + order_id + ".json"
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))
        file_path = DATA_FOLDER + "purchases/in progress/" + order_id + ".json"
        if os.path.exists(file_path):
            os.remove(file_path)

    def accept_receipt(self, notification_listener, blockchain, receipt_json=None):
        """
        Process the final receipt sent over by the buyer. If valid, broadcast the transaction
        to the bitcoin network.
        """
        self.notification_listener = notification_listener
        self.blockchain = blockchain
        if receipt_json:
            self.contract["buyer_receipt"] = json.loads(receipt_json,
                                                        object_pairs_hook=OrderedDict)
        contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
        del contract_dict["buyer_receipt"]
        contract_hash = digest(json.dumps(contract_dict, indent=4)).encode("hex")
        ref_hash = self.contract["buyer_receipt"]["receipt"]["ref_hash"]
        if ref_hash != contract_hash:
            raise Exception("Order number doesn't match")

        # The buyer may have sent over this whole contract, make sure the data we added wasn't manipulated.
        verify_key = self.keychain.signing_key.verify_key
        verify_key.verify(json.dumps(self.contract["vendor_order_confirmation"]["invoice"], indent=4),
                          unhexlify(self.contract["vendor_order_confirmation"]["signature"]))

        # TODO: verify buyer signature
        order_id = self.contract["vendor_order_confirmation"]["invoice"]["ref_hash"]
        if "moderator" in self.contract["buyer_order"]["order"]:
            outpoints = pickle.loads(self.db.Sales().get_outpoint(order_id))
            payout_address = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["address"]
            redeem_script = str(self.contract["buyer_order"]["order"]["payment"]["redeem_script"])
            for output in outpoints:
                del output["value"]
            value = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["value"]
            outs = [{'value': value, 'address': payout_address}]
            tx = bitcoin.mktx(outpoints, outs)

            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_b = self.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
            buyer_key = derive_childkey(masterkey_b, chaincode)

            vendor_sigs = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["signature(s)"]
            buyer_sigs = self.contract["buyer_receipt"]["receipt"]["payout"]["signature(s)"]
            for index in range(0, len(outpoints)):
                for s in vendor_sigs:
                    if s["input_index"] == index:
                        sig2 = str(s["signature"])
                for s in buyer_sigs:
                    if s["input_index"] == index:
                        sig1 = str(s["signature"])

                if bitcoin.verify_tx_input(tx, index, redeem_script, sig1, buyer_key):
                    tx_signed = bitcoin.apply_multisignatures(tx, index, str(redeem_script), sig1, sig2)
                else:
                    raise Exception("Buyer sent invalid signature")
            self.log.info("Broadcasting payout tx %s to network" % bitcoin.txhash(tx_signed))
            self.blockchain.broadcast(tx_signed)
            self.db.Sales().update_payment_tx(order_id, bitcoin.txhash(tx_signed))
            title = self.contract["vendor_offer"]["listing"]["item"]["title"]
            if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"]:
                image_hash = unhexlify(self.contract["vendor_offer"]["listing"]["item"]["image_hashes"][0])
            else:
                image_hash = ""
            buyer_guid = self.contract["buyer_order"]["order"]["id"]["guid"]
            if "blockchain_id" in self.contract["buyer_order"]["order"]["id"]:
                handle = self.contract["buyer_order"]["order"]["id"]["blockchain_id"]
            else:
                handle = ""
            self.notification_listener.notify(buyer_guid, handle, "payment received", order_id, title, image_hash)

        self.db.Sales().update_status(order_id, 3)
        file_path = DATA_FOLDER + "store/listings/trade receipts/" + order_id + ".json"
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))
        file_path = DATA_FOLDER + "store/listings/in progress/" + order_id + ".json"
        if os.path.exists(file_path):
            os.remove(file_path)

        return order_id

    def await_funding(self, notification_listener, libbitcoin_client, proofSig, is_purchase=True):
        """
        Saves the contract to the file system and db as an unfunded contract.
        Listens on the libbitcoin server for the multisig address to be funded.
        """

        self.notification_listener = notification_listener
        self.blockchain = libbitcoin_client
        self.is_purchase = is_purchase
        order_id = digest(json.dumps(self.contract, indent=4)).encode("hex")
        payment_address = self.contract["buyer_order"]["order"]["payment"]["address"]
        vendor_item = self.contract["vendor_offer"]["listing"]["item"]
        if "image_hashes" in vendor_item:
            thumbnail_hash = vendor_item["image_hashes"][0]
        else:
            thumbnail_hash = ""
        if "blockchain_id" in self.contract["vendor_offer"]["listing"]["id"] \
                and self.contract["vendor_offer"]["listing"]["id"]["blockchain_id"] != "":
            vendor = self.contract["vendor_offer"]["listing"]["id"]["blockchain_id"]
        else:
            vendor = self.contract["vendor_offer"]["listing"]["id"]["guid"]
        if "blockchain_id" in self.contract["buyer_order"]["order"]["id"] \
                and self.contract["buyer_order"]["order"]["id"]["blockchain_id"] != "":
            buyer = self.contract["buyer_order"]["order"]["id"]["blockchain_id"]
        else:
            buyer = self.contract["buyer_order"]["order"]["id"]["guid"]
        if is_purchase:
            file_path = DATA_FOLDER + "purchases/unfunded/" + order_id + ".json"
            self.db.Purchases().new_purchase(order_id,
                                             self.contract["vendor_offer"]["listing"]["item"]["title"],
                                             self.contract["vendor_offer"]["listing"]["item"]["description"],
                                             time.time(),
                                             self.contract["buyer_order"]["order"]["payment"]["amount"],
                                             payment_address,
                                             0,
                                             thumbnail_hash,
                                             vendor,
                                             proofSig,
                                             self.contract["vendor_offer"]["listing"]["metadata"]["category"])
        else:
            file_path = DATA_FOLDER + "store/listings/unfunded/" + order_id + ".json"
            self.db.Sales().new_sale(order_id,
                                     self.contract["vendor_offer"]["listing"]["item"]["title"],
                                     self.contract["vendor_offer"]["listing"]["item"]["description"],
                                     time.time(),
                                     self.contract["buyer_order"]["order"]["payment"]["amount"],
                                     payment_address,
                                     0,
                                     thumbnail_hash,
                                     buyer,
                                     self.contract["vendor_offer"]["listing"]["metadata"]["category"])

        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))
        self.blockchain.subscribe_address(str(payment_address), notification_cb=self.on_tx_received)

    def on_tx_received(self, address_version, address_hash, height, block_hash, tx):
        """
        Fire when the libbitcoin server tells us we received a payment to this funding address.
        While unlikely, a user may send multiple transactions to the funding address to reach the
        funding level. We need to keep a running balance and increment it when a new transaction
        is received. If the contract is fully funded, we push a notification to the websockets.
        """
        try:
            # decode the transaction
            self.log.info("Bitcoin transaction detected")
            transaction = deserialize(tx.encode("hex"))

            # get the amount (in satoshi) the user is expected to pay
            amount_to_pay = int(float(self.contract["buyer_order"]["order"]["payment"]["amount"]) * 100000000)
            if tx not in self.received_txs:  # make sure we aren't parsing the same tx twice.
                if "moderator" in self.contract["buyer_order"]["order"]:
                    output_script = 'a914' + digest(unhexlify(
                        self.contract["buyer_order"]["order"]["payment"]["redeem_script"])).encode("hex") + '87'
                else:
                    output_script = '76a914' + bitcoin.b58check_to_hex(
                        self.contract["buyer_order"]["order"]["payment"]["address"]) +'88ac'
                for output in transaction["outs"]:
                    if output["script"] == output_script:
                        self.amount_funded += output["value"]
                        if tx not in self.received_txs:
                            self.received_txs.append(tx)
                        self.outpoints.append({"output": bitcoin.txhash(tx.encode("hex")) +
                                                         ":" + str(output["index"]), "value": output["value"]})
                if self.amount_funded >= amount_to_pay:  # if fully funded
                    self.blockchain.unsubscribe_address(
                        self.contract["buyer_order"]["order"]["payment"]["address"], self.on_tx_received)
                    order_id = digest(json.dumps(self.contract, indent=4)).encode("hex")
                    title = self.contract["vendor_offer"]["listing"]["item"]["title"]
                    if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"]:
                        image_hash = unhexlify(self.contract["vendor_offer"]["listing"]["item"]["image_hashes"][0])
                    else:
                        image_hash = ""
                    if self.is_purchase:
                        unfunded_path = DATA_FOLDER + "purchases/unfunded/" + order_id + ".json"
                        in_progress_path = DATA_FOLDER + "purchases/in progress/" + order_id + ".json"
                        if "blockchain_id" in self.contract["vendor_offer"]["listing"]["id"]:
                            handle = self.contract["vendor_offer"]["listing"]["id"]["blockchain_id"]
                        else:
                            handle = ""
                        vendor_guid = self.contract["vendor_offer"]["listing"]["id"]["guid"]
                        self.notification_listener.notify(unhexlify(vendor_guid), handle, "payment received",
                                                          order_id, title, image_hash)
                        # update the db
                        self.db.Purchases().update_status(order_id, 1)
                        self.db.Purchases().update_outpoint(order_id, pickle.dumps(self.outpoints))
                        self.log.info("Payment for order id %s successfully broadcast to network." % order_id)
                    else:
                        unfunded_path = DATA_FOLDER + "store/listings/unfunded/" + order_id + ".json"
                        in_progress_path = DATA_FOLDER + "store/listings/in progress/" + order_id + ".json"
                        buyer_guid = self.contract["buyer_order"]["order"]["id"]["guid"]
                        if "blockchain_id" in self.contract["buyer_order"]["order"]["id"]:
                            handle = self.contract["buyer_order"]["order"]["id"]["blockchain_id"]
                        else:
                            handle = ""
                        self.notification_listener.notify(unhexlify(buyer_guid), handle, "new order", order_id,
                                                          title, image_hash)
                        self.db.Sales().update_status(order_id, 1)
                        self.db.Sales().update_outpoint(order_id, pickle.dumps(self.outpoints))
                        self.log.info("Received new order %s" % order_id)

                    os.rename(unfunded_path, in_progress_path)
        except Exception:
            self.log.critical("Error processing bitcoin transaction")

    def get_contract_id(self):
        contract = json.dumps(self.contract, indent=4)
        return digest(contract)

    def delete(self, delete_images=False):
        """
        Deletes the contract json from the OpenBazaar directory as well as the listing
        metadata from the db and all the related images in the file system.
        """

        # get the file path
        h = self.db.HashMap()
        file_path = h.get_file(digest(json.dumps(self.contract, indent=4)).encode("hex"))

        # maybe delete the images from disk
        if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"] and delete_images:
            for image_hash in self.contract["vendor_offer"]["listing"]["item"]["image_hashes"]:
                # delete from disk
                image_path = h.get_file(image_hash)
                if os.path.exists(image_path):
                    os.remove(image_path)
                # remove pointer to the image from the HashMap
                h.delete(image_hash)

        # delete the contract from disk
        if os.path.exists(file_path):
            os.remove(file_path)

        # delete the listing metadata from the db
        contract_hash = digest(json.dumps(self.contract, indent=4))
        self.db.ListingsStore().delete_listing(contract_hash)

        # remove the pointer to the contract from the HashMap
        h.delete(contract_hash.encode("hex"))

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
        file_name += digest(json.dumps(self.contract, indent=4)).encode("hex")[:8]

        # save the json contract to the file system
        file_path = DATA_FOLDER + "store/listings/contracts/" + file_name + ".json"
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))

        # Create a `ListingMetadata` protobuf object using data from the full contract
        listings = Listings()
        data = listings.ListingMetadata()
        data.contract_hash = digest(json.dumps(self.contract, indent=4))
        vendor_item = self.contract["vendor_offer"]["listing"]["item"]
        data.title = vendor_item["title"]
        if "image_hashes" in vendor_item:
            data.thumbnail_hash = unhexlify(vendor_item["image_hashes"][0])
        if "category" in vendor_item:
            data.category = vendor_item["category"]
        if "bitcoin" not in vendor_item["price_per_unit"]:
            data.price = float(vendor_item["price_per_unit"]["fiat"]["price"])
            data.currency_code = vendor_item["price_per_unit"]["fiat"][
                "currency_code"]
        else:
            data.price = float(vendor_item["price_per_unit"]["bitcoin"])
            data.currency_code = "BTC"
        data.nsfw = vendor_item["nsfw"]
        if "shipping" not in self.contract["vendor_offer"]["listing"]:
            data.origin = CountryCode.Value("NA")
        else:
            data.origin = CountryCode.Value(
                self.contract["vendor_offer"]["listing"]["shipping"]["shipping_origin"].upper())
            for region in self.contract["vendor_offer"]["listing"]["shipping"]["shipping_regions"]:
                data.ships_to.append(CountryCode.Value(region.upper()))

        # save the mapping of the contract file path and contract hash in the database
        self.db.HashMap().insert(data.contract_hash.encode("hex"), file_path)

        # save the `ListingMetadata` protobuf to the database as well
        self.db.ListingsStore().add_listing(data)

    def verify(self, sender_key):
        """
        Validate that an order sent over by a buyer is filled out correctly.
        """

        try:
            contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
            del contract_dict["buyer_order"]
            contract_hash = digest(json.dumps(contract_dict, indent=4))

            ref_hash = unhexlify(self.contract["buyer_order"]["order"]["ref_hash"])

            # verify that the reference hash matches the contract and that the contract actually exists
            if contract_hash != ref_hash or not self.db.HashMap().get_file(ref_hash.encode("hex")):
                raise Exception("Order for contract that doesn't exist")

            # verify the signature on the order
            verify_key = nacl.signing.VerifyKey(sender_key)
            verify_key.verify(json.dumps(self.contract["buyer_order"]["order"], indent=4),
                              unhexlify(self.contract["buyer_order"]["signature"]))

            # TODO: verify the bitcoin signature after we add it

            # verify buyer included the correct bitcoin amount for payment
            quantity = int(self.contract["buyer_order"]["order"]["quantity"])
            price_json = self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]
            if "bitcoin" in price_json:
                asking_price = float(price_json["bitcoin"]) * quantity
            else:
                currency_code = price_json["fiat"]["currency_code"]
                fiat_price = price_json["fiat"]["price"]
                request = Request('https://api.bitcoinaverage.com/ticker/' + currency_code.upper() + '/last')
                response = urlopen(request)
                conversion_rate = response.read()
                asking_price = float("{0:.8f}".format(float(fiat_price) / float(conversion_rate))) * quantity

            if "shipping" in self.contract["vendor_offer"]["listing"]:
                if not self.contract["vendor_offer"]["listing"]["shipping"]["free"]:
                    shipping_origin = self.contract["vendor_offer"]["listing"]["shipping"][
                        "shipping_origin"].upper()
                    if shipping_origin == self.contract["buyer_order"]["order"]["shipping"]["country"].upper():
                        if "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                            shipping_amount = float(self.contract["vendor_offer"]["listing"]["shipping"][
                                "flat_fee"]["bitcoin"]["domestic"]) * quantity
                        else:
                            price = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"][
                                "price"]["domestic"]
                            currency = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                                "fiat"]["currency_code"]
                            try:
                                request = Request('https://api.bitcoinaverage.com/ticker/' +
                                                  currency.upper() + '/last')
                                response = urlopen(request)
                                conversion_rate = response.read()
                            except URLError:
                                return False
                            shipping_amount = round(float("{0:.8f}".format(float(price) /
                                                                           float(conversion_rate))) * quantity, 8)
                    else:
                        if "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                            shipping_amount = float(self.contract["vendor_offer"]["listing"]["shipping"][
                                "flat_fee"]["bitcoin"]["international"]) * quantity
                        else:
                            price = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"][
                                "price"]["international"]
                            currency = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                                "fiat"]["currency_code"]
                            try:
                                request = Request('https://api.bitcoinaverage.com/ticker/' +
                                                  currency.upper() + '/last')
                                response = urlopen(request)
                                conversion_rate = response.read()
                            except URLError:
                                return False
                            shipping_amount = round(float("{0:.8f}".format(float(price) /
                                                                           float(conversion_rate))) * quantity, 8)
                    asking_price += shipping_amount

            if float(asking_price) > float(self.contract["buyer_order"]["order"]["payment"]["amount"]):
                raise Exception("Insuffient Payment")

            if "moderator" in self.contract["buyer_order"]["order"]:
                # verify a valid moderator was selected
                valid_mod = False
                for mod in self.contract["vendor_offer"]["listing"]["moderators"]:
                    if mod["guid"] == self.contract["buyer_order"]["order"]["moderator"]:
                        valid_mod = True
                if not valid_mod:
                    raise Exception("Invalid moderator")
                # verify redeem script
                chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
                for mod in self.contract["vendor_offer"]["listing"]["moderators"]:
                    if mod["guid"] == self.contract["buyer_order"]["order"]["moderator"]:
                        masterkey_m = mod["pubkeys"]["bitcoin"]["key"]

                masterkey_b = self.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
                masterkey_v = bitcoin.bip32_extract_key(self.keychain.bitcoin_master_pubkey)
                buyer_key = derive_childkey(masterkey_b, chaincode)
                vendor_key = derive_childkey(masterkey_v, chaincode)
                moderator_key = derive_childkey(masterkey_m, chaincode)

                redeem_script = bitcoin.mk_multisig_script([buyer_key, vendor_key, moderator_key], 2)
                if redeem_script != self.contract["buyer_order"]["order"]["payment"]["redeem_script"]:
                    raise Exception("Invalid redeem script")
            else:
                # verify the direct payment address
                chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]

                masterkey_v = bitcoin.bip32_extract_key(self.keychain.bitcoin_master_pubkey)
                vendor_key = derive_childkey(masterkey_v, chaincode)

                # verify the payment address
                if self.testnet:
                    payment_address = bitcoin.pubkey_to_address(vendor_key, 111)
                else:
                    payment_address = bitcoin.pubkey_to_address(vendor_key)
                if payment_address != self.contract["buyer_order"]["order"]["payment"]["address"]:
                    raise Exception("Incorrect payment address")

            # verify all the shipping fields exist
            if self.contract["vendor_offer"]["listing"]["metadata"]["category"] == "physical good":
                shipping = self.contract["buyer_order"]["order"]["shipping"]
                keys = ["ship_to", "address", "postal_code", "city", "state", "country"]
                for value in map(shipping.get, keys):
                    if value is None:
                        raise Exception("Missing shipping field")

            # verify buyer ID
            pubkeys = self.contract["buyer_order"]["order"]["id"]["pubkeys"]
            keys = ["guid", "bitcoin", "encryption"]
            for value in map(pubkeys.get, keys):
                if value is None:
                    raise Exception("Missing pubkey field")

            return True

        except Exception:
            return False

    def __repr__(self):
        return json.dumps(self.contract, indent=4)
