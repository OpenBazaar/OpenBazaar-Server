__author__ = 'chris'

import base64
import bitcointools
import json
import nacl.encoding
import nacl.signing
import os
import random
import re
import time
from binascii import unhexlify
from bitcoin import SelectParams
from bitcoin.core.script import CScript, OP_2, OP_3, OP_CHECKMULTISIG
from bitcoin.wallet import P2SHBitcoinAddress, P2PKHBitcoinAddress, CBitcoinAddress
from collections import OrderedDict
from config import DATA_FOLDER, TRANSACTION_FEE
from copy import deepcopy
from datetime import datetime
from dht.utils import digest
from hashlib import sha256
from keys.bip32utils import derive_childkey
from keys.keychain import KeyChain
from log import Logger
from market.profile import Profile
from market.btcprice import BtcPrice
from market.transactions import BitcoinTransaction
from protos.countries import CountryCode
from protos.objects import Listings
from market.smtpnotification import SMTPNotification


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
            hash_value: a hash160 of a contract
            testnet: is this contract on the testnet
        """
        self.db = database
        self.keychain = KeyChain(self.db)
        if contract is not None:
            self.contract = contract
        elif hash_value is not None:
            try:
                file_path = self.db.filemap.get_file(hash_value.encode("hex"))
                if file_path is None:
                    file_path = os.path.join(DATA_FOLDER, "cache", hash_value.encode("hex"))
                with open(file_path, 'r') as filename:
                    self.contract = json.load(filename, object_pairs_hook=OrderedDict)
            except Exception:
                file_name = hash_value.encode("hex") + ".json"
                if os.path.exists(os.path.join(DATA_FOLDER, "purchases", "unfunded", file_name)):
                    file_path = os.path.join(DATA_FOLDER, "purchases", "unfunded", file_name)
                elif os.path.exists(os.path.join(DATA_FOLDER, "purchases", "in progress", file_name)):
                    file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", file_name)
                elif os.path.exists(os.path.join(DATA_FOLDER, "purchases", "trade receipts", file_name)):
                    file_path = os.path.join(DATA_FOLDER, "purchases", "trade receipts", file_name)
                elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", file_name)):
                    file_path = os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", file_name)
                elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "in progress", file_name)):
                    file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", file_name)
                elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "trade receipts", file_name)):
                    file_path = os.path.join(DATA_FOLDER, "store", "contracts", "trade receipts", file_name)

                try:
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
               pinned,
               max_quantity,
               hidden,
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
               moderators=None,
               contract_id=None):
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
        if contract_id is not None and contract_id != "":
            self.previous_title = self.contract["vendor_offer"]["listing"]["item"]["title"]
        else:
            self.previous_title = None
            contract_id = digest(random.getrandbits(255)).encode("hex")

        self.contract = OrderedDict(
            {
                "vendor_offer": {
                    "listing": {
                        "contract_id": contract_id,
                        "metadata": {
                            "version": "1",
                            "category": metadata_category.lower(),
                            "category_sub": "fixed price",
                            "last_modified": int(time.time()),
                            "pinned": pinned,
                            "max_quantity": max_quantity,
                            "hidden": hidden
                        },
                        "id": {
                            "guid": self.keychain.guid.encode("hex"),
                            "pubkeys": {
                                "guid": self.keychain.verify_key.encode(encoder=nacl.encoding.HexEncoder),
                                "bitcoin": bitcointools.bip32_extract_key(self.keychain.bitcoin_master_pubkey)
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
        if profile.handle != "":
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
                mod_info = self.db.moderators.get_moderator(mod)
                if mod_info is not None:
                    moderator = {
                        "guid": mod,
                        "name": mod_info[5],
                        "avatar": mod_info[7].encode("hex"),
                        "short_description": mod_info[6],
                        "fee": str(mod_info[8]) + "%",
                        "blockchain_id": mod_info[4],
                        "pubkeys": {
                            "guid": mod_info[1].encode("hex"),
                            "bitcoin": {
                                "key": mod_info[2].encode("hex"),
                                "signature": base64.b64encode(mod_info[3])
                            }
                        }
                    }
                    self.contract["vendor_offer"]["listing"]["moderators"].append(moderator)

        listing = json.dumps(self.contract["vendor_offer"]["listing"], indent=4)
        self.contract["vendor_offer"]["signatures"] = {}
        self.contract["vendor_offer"]["signatures"]["guid"] = \
            base64.b64encode(self.keychain.signing_key.sign(listing)[:64])
        self.contract["vendor_offer"]["signatures"]["bitcoin"] = \
            bitcointools.encode_sig(*bitcointools.ecdsa_raw_sign(
                listing, bitcointools.bip32_extract_key(self.keychain.bitcoin_master_privkey)))
        self.save()

    def add_purchase_info(self,
                          quantity,
                          refund_address,
                          ship_to=None,
                          shipping_address=None,
                          city=None,
                          state=None,
                          postal_code=None,
                          country=None,
                          moderator=None,
                          options=None,
                          alternate_contact=None):
        """
        Update the contract with the buyer's purchase information.
        """

        if not self.testnet and not (refund_address[:1] == "1" or refund_address[:1] == "3"):
            raise Exception("Bitcoin address is not a mainnet address")
        elif self.testnet and not \
                (refund_address[:1] == "n" or refund_address[:1] == "m" or refund_address[:1] == "2"):
            raise Exception("Bitcoin address is not a testnet address")
        try:
            bitcointools.b58check_to_hex(refund_address)
        except AssertionError:
            raise Exception("Invalid Bitcoin address")

        if "max_quantity" in self.contract["vendor_offer"]["listing"]["metadata"]:
            if quantity > int(self.contract["vendor_offer"]["listing"]["metadata"]["max_quantity"]):
                raise Exception("Quantity exceeds max quantity in listing")

        profile = Profile(self.db).get()
        order_json = {
            "buyer_order": {
                "order": {
                    "ref_hash": digest(json.dumps(self.contract, indent=4)).encode("hex"),
                    "date": str(datetime.utcnow()) + " UTC",
                    "quantity": quantity,
                    "id": {
                        "guid": self.keychain.guid.encode("hex"),
                        "pubkeys": {
                            "guid": self.keychain.verify_key.encode(encoder=nacl.encoding.HexEncoder),
                            "bitcoin": bitcointools.bip32_extract_key(self.keychain.bitcoin_master_pubkey),
                        }
                    },
                    "payment": {},
                    "refund_address": refund_address,
                    "alternate_contact": alternate_contact if alternate_contact is not None else ""
                }
            }
        }
        SelectParams("testnet" if self.testnet else "mainnet")
        if profile.handle != "":
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
            masterkey_b = bitcointools.bip32_extract_key(self.keychain.bitcoin_master_pubkey)
            masterkey_v = self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
            buyer_key = unhexlify(derive_childkey(masterkey_b, chaincode))
            vendor_key = unhexlify(derive_childkey(masterkey_v, chaincode))
            moderator_key = unhexlify(derive_childkey(masterkey_m, chaincode))

            redeem_script = CScript([OP_2, buyer_key, vendor_key, moderator_key, OP_3, OP_CHECKMULTISIG])
            order_json["buyer_order"]["order"]["payment"]["redeem_script"] = redeem_script.encode("hex")
            payment_address = str(P2SHBitcoinAddress.from_redeemScript(redeem_script))
            order_json["buyer_order"]["order"]["payment"]["address"] = payment_address
            order_json["buyer_order"]["order"]["payment"]["refund_tx_fee"] = TRANSACTION_FEE
        else:
            chaincode = sha256(str(random.getrandbits(256))).digest().encode("hex")
            order_json["buyer_order"]["order"]["payment"]["chaincode"] = chaincode

            masterkey_v = self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
            vendor_key = unhexlify(derive_childkey(masterkey_v, chaincode))

            payment_address = str(P2PKHBitcoinAddress.from_pubkey(vendor_key))
            order_json["buyer_order"]["order"]["payment"]["address"] = payment_address

        price_json = self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]
        if "bitcoin" in price_json:
            amount_to_pay = float(price_json["bitcoin"]) * quantity
        else:
            currency_code = price_json["fiat"]["currency_code"]
            fiat_price = price_json["fiat"]["price"]
            conversion_rate = BtcPrice.instance().get(currency_code.upper())
            amount_to_pay = float("{0:.8f}".format(float(fiat_price) / float(conversion_rate))) * quantity
        if "shipping" in self.contract["vendor_offer"]["listing"]:
            if not self.contract["vendor_offer"]["listing"]["shipping"]["free"]:
                shipping_origin = str(self.contract["vendor_offer"]["listing"]["shipping"][
                    "shipping_origin"].upper())
                if shipping_origin == country.upper():
                    if "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                        shipping_amount = float(self.contract["vendor_offer"]["listing"][
                            "shipping"]["flat_fee"]["bitcoin"]["domestic"]) * quantity
                    else:
                        price = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"][
                            "price"]["domestic"]
                        currency = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                            "fiat"]["currency_code"]
                        conversion_rate = BtcPrice.instance().get(currency.upper(), False)
                        shipping_amount = float("{0:.8f}".format(float(price) / float(conversion_rate))) * quantity
                else:
                    if "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                        shipping_amount = float(self.contract["vendor_offer"]["listing"]["shipping"][
                            "flat_fee"]["bitcoin"]["international"]) * quantity
                    else:
                        price = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"][
                            "price"]["international"]
                        currency = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                            "fiat"]["currency_code"]

                        conversion_rate = BtcPrice.instance().get(currency.upper(), False)
                        shipping_amount = float("{0:.8f}".format(float(price) / float(conversion_rate))) * quantity
                amount_to_pay += shipping_amount

        if round(amount_to_pay, 8) < round(TRANSACTION_FEE / float(100000000), 8):
            raise Exception("Contract price is below transaction fee.")

        order_json["buyer_order"]["order"]["payment"]["amount"] = round(amount_to_pay, 8)
        self.contract["buyer_order"] = order_json["buyer_order"]

        order = json.dumps(self.contract["buyer_order"]["order"], indent=4)
        self.contract["buyer_order"]["signatures"] = {}
        self.contract["buyer_order"]["signatures"]["guid"] = \
            base64.b64encode(self.keychain.signing_key.sign(order)[:64])
        self.contract["buyer_order"]["signatures"]["bitcoin"] = \
            bitcointools.encode_sig(*bitcointools.ecdsa_raw_sign(
                order, bitcointools.bip32_extract_key(self.keychain.bitcoin_master_privkey)))

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
            bitcointools.b58check_to_hex(payout_address)
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
        outpoints = json.loads(self.db.sales.get_outpoint(order_id))
        if "moderator" in self.contract["buyer_order"]["order"]:
            redeem_script = self.contract["buyer_order"]["order"]["payment"]["redeem_script"]
            tx = BitcoinTransaction.make_unsigned(outpoints, payout_address, testnet=self.testnet)
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_v = bitcointools.bip32_extract_key(self.keychain.bitcoin_master_privkey)
            vendor_priv = derive_childkey(masterkey_v, chaincode, bitcointools.MAINNET_PRIVATE)
            sigs = tx.create_signature(vendor_priv, redeem_script)
            conf_json["vendor_order_confirmation"]["invoice"]["payout"] = {}
            conf_json["vendor_order_confirmation"]["invoice"]["payout"]["address"] = payout_address
            conf_json["vendor_order_confirmation"]["invoice"]["payout"]["value"] = tx.get_out_value()
            conf_json["vendor_order_confirmation"]["invoice"]["payout"]["signature(s)"] = sigs
        else:
            tx = BitcoinTransaction.make_unsigned(outpoints, payout_address, testnet=self.testnet)
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_v = bitcointools.bip32_extract_key(self.keychain.bitcoin_master_privkey)
            vendor_priv = derive_childkey(masterkey_v, chaincode, bitcointools.MAINNET_PRIVATE)
            tx.sign(vendor_priv)
            tx.broadcast(self.blockchain)
            self.db.transactions.add_transaction(tx.to_raw_tx())
            self.log.info("broadcasting payout tx %s to network" % tx.get_hash())
            self.db.sales.update_payment_tx(order_id, tx.get_hash())
            self.blockchain.unsubscribe_address(
                self.contract["buyer_order"]["order"]["payment"]["address"], self.on_tx_received)

        confirmation = json.dumps(conf_json["vendor_order_confirmation"]["invoice"], indent=4)
        conf_json["vendor_order_confirmation"]["signature"] = \
            base64.b64encode(self.keychain.signing_key.sign(confirmation)[:64])

        self.contract["vendor_order_confirmation"] = conf_json["vendor_order_confirmation"]
        self.db.sales.update_status(order_id, 2)
        file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", order_id + ".json")
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))

    def accept_order_confirmation(self, notification_listener, confirmation_json=None):
        """
        Validate the order confirmation sent over from the vendor and update our node accordingly.
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
            status = self.db.purchases.get_status(contract_hash)
            if status == 2 or status == 3:
                raise Exception("Order confirmation already processed for this contract")

            # update the order status in the db
            self.db.purchases.update_status(contract_hash, 2)
            self.db.purchases.status_changed(contract_hash, 1)
            file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", contract_hash + ".json")

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

            # Send SMTP notification
            notification = SMTPNotification(self.db)
            notification.send("[OpenBazaar] Order Confirmed and Shipped",
                              "You have received an order confirmation.<br><br>"
                              "Order: %s<br>Vendor: %s<br>Title: %s<br>" % (contract_hash, vendor_guid, title))

            return True
        except Exception, e:
            return e.message

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
                    anonymous=True):

        """
        Add the final piece of the contract that appends the review and payout transaction.
        """
        self.blockchain = libbitcoin_client
        contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
        if "dispute" in contract_dict:
            del contract_dict["dispute"]
        if "dispute_resolution" in contract_dict:
            del contract_dict["dispute_resolution"]
        reference_hash = digest(json.dumps(contract_dict, indent=4)).encode("hex")
        receipt_json = {
            "buyer_receipt": {
                "receipt": {
                    "ref_hash": reference_hash,
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
        if "vendor_order_confirmation" in self.contract:
            order_id = self.contract["vendor_order_confirmation"]["invoice"]["ref_hash"]
        else:
            order_id = self.get_order_id()
        if None not in (feedback, quality, description, delivery_time, customer_service):
            address = self.contract["buyer_order"]["order"]["payment"]["address"]
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_b = self.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
            buyer_pub = derive_childkey(masterkey_b, chaincode)
            buyer_priv = derive_childkey(bitcointools.bip32_extract_key(self.keychain.bitcoin_master_privkey),
                                         chaincode, bitcointools.MAINNET_PRIVATE)
            amount = self.contract["buyer_order"]["order"]["payment"]["amount"]
            listing_hash = self.contract["vendor_offer"]["listing"]["contract_id"]

            receipt_json["buyer_receipt"]["receipt"]["rating"] = OrderedDict()
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"] = OrderedDict()
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["feedback"] = feedback
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["quality"] = quality
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["description"] = description
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["delivery_time"] = delivery_time
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["customer_service"] = customer_service
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["review"] = review
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["address"] = address
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["buyer_key"] = buyer_pub
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["amount"] = amount
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["listing"] = listing_hash
            receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["proof_of_tx"] = \
                base64.b64encode(self.db.purchases.get_proof_sig(order_id))
            if not anonymous:
                receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["buyer_guid"] = \
                    self.keychain.guid.encode("hex")
                receipt_json["buyer_receipt"]["receipt"]["rating"]["tx_summary"]["buyer_guid_key"] = \
                    self.keychain.verify_key.encode(encoder=nacl.encoding.HexEncoder)

        status = self.db.purchases.get_status(order_id)
        if status < 3 and "moderator" in self.contract["buyer_order"]["order"]:
            outpoints = json.loads(self.db.purchases.get_outpoint(order_id))
            payout_address = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["address"]
            redeem_script = str(self.contract["buyer_order"]["order"]["payment"]["redeem_script"])
            value = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["value"]
            tx = BitcoinTransaction.make_unsigned(outpoints, payout_address,
                                                  testnet=self.testnet, out_value=value)
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_b = bitcointools.bip32_extract_key(self.keychain.bitcoin_master_privkey)
            buyer_priv = derive_childkey(masterkey_b, chaincode, bitcointools.MAINNET_PRIVATE)

            buyer_signatures = tx.create_signature(buyer_priv, redeem_script)
            signatures = []
            for i in range(len(outpoints)):
                for vendor_sig in self.contract["vendor_order_confirmation"]["invoice"]["payout"]["signature(s)"]:
                    if vendor_sig["index"] == i:
                        v_signature = vendor_sig["signature"]
                for buyer_sig in buyer_signatures:
                    if buyer_sig["index"] == i:
                        b_signature = buyer_sig["signature"]
                signature_obj = {"index": i, "signatures": [b_signature, v_signature]}
                signatures.append(signature_obj)

            receipt_json["buyer_receipt"]["receipt"]["payout"] = {}
            tx.multisign(signatures, redeem_script)
            tx.broadcast(self.blockchain)
            self.db.transactions.add_transaction(tx.to_raw_tx())
            self.blockchain.unsubscribe_address(
                self.contract["buyer_order"]["order"]["payment"]["address"], self.on_tx_received)

            self.log.info("broadcasting payout tx %s to network" % tx.get_hash())
            receipt_json["buyer_receipt"]["receipt"]["payout"]["txid"] = tx.get_hash()

            receipt_json["buyer_receipt"]["receipt"]["payout"]["signature(s)"] = buyer_signatures
            receipt_json["buyer_receipt"]["receipt"]["payout"]["value"] = tx.get_out_value()
        if claim:
            receipt_json["buyer_receipt"]["receipt"]["dispute"]["claim"] = claim
        receipt = json.dumps(receipt_json["buyer_receipt"]["receipt"], indent=4)
        receipt_json["buyer_receipt"]["signature"] = \
            base64.b64encode(self.keychain.signing_key.sign(receipt)[:64])
        self.contract["buyer_receipt"] = receipt_json["buyer_receipt"]

        if "rating" in self.contract["buyer_receipt"]["receipt"]:
            self.contract["buyer_receipt"]["receipt"]["rating"]["signature"] = \
                bitcointools.encode_sig(*bitcointools.ecdsa_raw_sign(json.dumps(
                    self.contract["buyer_receipt"]["receipt"]["rating"]["tx_summary"], indent=4), buyer_priv))
            if not anonymous:
                self.contract["buyer_receipt"]["receipt"]["rating"]["guid_signature"] = \
                    base64.b64encode(self.keychain.signing_key.sign(json.dumps(
                        self.contract["buyer_receipt"]["receipt"]["rating"]["tx_summary"], indent=4))[:64])

        if status < 3:
            self.db.purchases.update_status(order_id, 3)
            file_path = os.path.join(DATA_FOLDER, "purchases", "trade receipts", order_id + ".json")
            with open(file_path, 'w') as outfile:
                outfile.write(json.dumps(self.contract, indent=4))
            file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", order_id + ".json")
            if os.path.exists(file_path):
                os.remove(file_path)
        else:
            file_path = os.path.join(DATA_FOLDER, "purchases", "trade receipts", order_id + ".json")
            with open(file_path, 'wb') as outfile:
                outfile.write(json.dumps(self.contract, indent=4))

    def accept_receipt(self, notification_listener, blockchain, receipt_json=None):
        """
        Process the final receipt sent over by the buyer. If valid, broadcast the transaction
        to the bitcoin network.
        """
        self.notification_listener = notification_listener
        self.blockchain = blockchain
        if "buyer_receipt" in self.contract:
            raise Exception("A receipt has already been processed for this order")
        if receipt_json:
            self.contract["buyer_receipt"] = json.loads(receipt_json,
                                                        object_pairs_hook=OrderedDict)

        contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
        del contract_dict["buyer_receipt"]
        if "dispute" in contract_dict:
            del contract_dict["dispute"]
        if "dispute_resolution" in contract_dict:
            del contract_dict["dispute_resolution"]
        contract_hash = digest(json.dumps(contract_dict, indent=4)).encode("hex")
        ref_hash = self.contract["buyer_receipt"]["receipt"]["ref_hash"]
        if ref_hash != contract_hash:
            raise Exception("Order number doesn't match")

        # TODO: verify buyer signature
        if "vendor_order_confirmation" in self.contract:
            order_id = self.contract["vendor_order_confirmation"]["invoice"]["ref_hash"]
        else:
            order_id = self.get_order_id()

        status = self.db.sales.get_status(order_id)
        if status not in (2, 5, 6):
            raise Exception("Can only process a receipt after an order confirmation "
                            "is sent or a dispute is finalized")

        title = self.contract["vendor_offer"]["listing"]["item"]["title"]
        if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"]:
            image_hash = unhexlify(self.contract["vendor_offer"]["listing"]["item"]["image_hashes"][0])
        else:
            image_hash = ""
        buyer_guid = unhexlify(self.contract["buyer_order"]["order"]["id"]["guid"])
        if "blockchain_id" in self.contract["buyer_order"]["order"]["id"]:
            handle = self.contract["buyer_order"]["order"]["id"]["blockchain_id"]
        else:
            handle = ""

        if "moderator" in self.contract["buyer_order"]["order"] and status not in (5, 6):
            outpoints = json.loads(self.db.sales.get_outpoint(order_id))
            payout_address = str(self.contract["vendor_order_confirmation"]["invoice"]["payout"]["address"])
            redeem_script = str(self.contract["buyer_order"]["order"]["payment"]["redeem_script"])
            value = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["value"]

            tx = BitcoinTransaction.make_unsigned(outpoints, payout_address,
                                                  testnet=self.testnet, out_value=value)

            vendor_sigs = self.contract["vendor_order_confirmation"]["invoice"]["payout"]["signature(s)"]
            buyer_sigs = self.contract["buyer_receipt"]["receipt"]["payout"]["signature(s)"]

            signatures = []
            for i in range(len(outpoints)):
                for vendor_sig in vendor_sigs:
                    if vendor_sig["index"] == i:
                        v_signature = vendor_sig["signature"]
                for buyer_sig in buyer_sigs:
                    if buyer_sig["index"] == i:
                        b_signature = buyer_sig["signature"]
                signature_obj = {"index": i, "signatures": [b_signature, v_signature]}
                signatures.append(signature_obj)

            tx.multisign(signatures, redeem_script)
            tx.broadcast(self.blockchain)
            self.db.transactions.add_transaction(tx.to_raw_tx())
            self.blockchain.unsubscribe_address(
                self.contract["buyer_order"]["order"]["payment"]["address"], self.on_tx_received)
            self.log.info("broadcasting payout tx %s to network" % tx.get_hash())

            self.db.sales.update_payment_tx(order_id, tx.get_hash())

        self.notification_listener.notify(buyer_guid, handle, "rating received", order_id, title, image_hash)

        notification_rater = handle if handle else buyer_guid.encode('hex')

        notification = SMTPNotification(self.db)
        notification.send("[OpenBazaar] New Rating Received",
                          "You received a new rating from %s for Order #%s - \"%s\". " % (notification_rater,
                                                                                          order_id,
                                                                                          title))

        if "rating" in self.contract["buyer_receipt"]["receipt"]:
            self.db.ratings.add_rating(self.contract["buyer_receipt"]["receipt"]
                                       ["rating"]["tx_summary"]["listing"],
                                       json.dumps(self.contract["buyer_receipt"]["receipt"]["rating"], indent=4))

        if status == 2:
            self.db.sales.status_changed(order_id, 1)
            self.db.sales.update_status(order_id, 3)
        file_path = os.path.join(DATA_FOLDER, "store", "contracts", "trade receipts", order_id + ".json")
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))
        file_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", order_id + ".json")
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
            file_path = os.path.join(DATA_FOLDER, "purchases", "unfunded", order_id + ".json")
            self.db.purchases.new_purchase(order_id,
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
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", order_id + ".json")
            title = self.contract["vendor_offer"]["listing"]["item"]["title"]
            description = self.contract["vendor_offer"]["listing"]["item"]["description"]
            self.db.sales.new_sale(order_id,
                                   title,
                                   description,
                                   time.time(),
                                   self.contract["buyer_order"]["order"]["payment"]["amount"],
                                   payment_address,
                                   0,
                                   thumbnail_hash,
                                   buyer,
                                   self.contract["vendor_offer"]["listing"]["metadata"]["category"])

            try:
                notification = SMTPNotification(self.db)
                notification.send("[OpenBazaar] Order Received", "Order #%s<br>"
                                                                 "Buyer: %s<br>"
                                                                 "BTC Address: %s<br>"
                                                                 "Title: %s<br>"
                                                                 "Description: %s<br>"
                                  % (order_id, buyer, payment_address, title, description))
            except Exception as e:
                self.log.info("Error with SMTP notification: %s" % e.message)

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
            transaction = BitcoinTransaction.from_serialized(tx, self.testnet)

            # get the amount (in satoshi) the user is expected to pay
            amount_to_pay = int(float(self.contract["buyer_order"]["order"]["payment"]["amount"]) * 100000000)
            if tx not in self.received_txs:  # make sure we aren't parsing the same tx twice.
                outpoints = transaction.check_for_funding(
                    self.contract["buyer_order"]["order"]["payment"]["address"])
                if outpoints is not None:
                    for outpoint in outpoints:
                        self.amount_funded += outpoint["value"]
                        self.received_txs.append(tx)
                        self.outpoints.append(outpoint)
                if self.amount_funded >= amount_to_pay:  # if fully funded
                    self.payment_received()
                else:
                    order_id = digest(json.dumps(self.contract, indent=4)).encode("hex")
                    notification_json = {
                        "notification": {
                            "type": "partial payment",
                            "amount_funded": round(self.amount_funded / float(100000000), 8),
                            "order_id": order_id
                        }
                    }
                    self.notification_listener.push_ws(notification_json)

        except Exception as e:
            self.log.critical("Error processing bitcoin transaction: %s" % e.message)

    def payment_received(self):
        order_id = digest(json.dumps(self.contract, indent=4)).encode("hex")
        title = self.contract["vendor_offer"]["listing"]["item"]["title"]
        if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"]:
            image_hash = unhexlify(self.contract["vendor_offer"]["listing"]["item"]["image_hashes"][0])
        else:
            image_hash = ""
        if self.is_purchase:
            unfunded_path = os.path.join(DATA_FOLDER, "purchases", "unfunded", order_id + ".json")
            in_progress_path = os.path.join(DATA_FOLDER, "purchases", "in progress", order_id + ".json")
            if "blockchain_id" in self.contract["vendor_offer"]["listing"]["id"]:
                handle = self.contract["vendor_offer"]["listing"]["id"]["blockchain_id"]
            else:
                handle = ""
            vendor_guid = self.contract["vendor_offer"]["listing"]["id"]["guid"]
            self.notification_listener.notify(unhexlify(vendor_guid), handle, "payment received",
                                              order_id, title, image_hash)

            notification = SMTPNotification(self.db)
            notification.send("[OpenBazaar] Purchase Payment Received", "Your payment was received.<br><br>"
                                                                        "Order: %s<br>"
                                                                        "Vendor: %s<br>"
                                                                        "Title: %s"
                              % (order_id, vendor_guid, title))

            # update the db
            if self.db.purchases.get_status(order_id) == 0:
                self.db.purchases.update_status(order_id, 1)
            self.db.purchases.update_outpoint(order_id, json.dumps(self.outpoints))
            self.log.info("Payment for order id %s successfully broadcast to network." % order_id)
        else:
            unfunded_path = os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", order_id + ".json")
            in_progress_path = os.path.join(DATA_FOLDER, "store", "contracts", "in progress", order_id + ".json")
            buyer_guid = self.contract["buyer_order"]["order"]["id"]["guid"]
            if "blockchain_id" in self.contract["buyer_order"]["order"]["id"]:
                handle = self.contract["buyer_order"]["order"]["id"]["blockchain_id"]
            else:
                handle = ""
            self.notification_listener.notify(unhexlify(buyer_guid), handle, "new order", order_id,
                                              title, image_hash)

            notification = SMTPNotification(self.db)
            notification.send("[OpenBazaar] Payment for Order Received", "Payment was received for Order #%s."
                              % order_id)

            self.db.sales.update_status(order_id, 1)
            self.db.sales.status_changed(order_id, 1)
            self.db.sales.update_outpoint(order_id, json.dumps(self.outpoints))
            self.log.info("Received new order %s" % order_id)

        os.rename(unfunded_path, in_progress_path)

    def get_contract_id(self):
        return self.contract["vendor_offer"]["listing"]["contract_id"]

    def get_order_id(self):
        contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
        if "vendor_order_confirmation" in contract_dict:
            del contract_dict["vendor_order_confirmation"]
        if "buyer_receipt" in contract_dict:
            del contract_dict["buyer_receipt"]
        if "dispute" in contract_dict:
            del contract_dict["dispute"]
        if "dispute_resolution" in contract_dict:
            del contract_dict["dispute_resolution"]
        return digest(json.dumps(contract_dict, indent=4)).encode("hex")

    def check_expired(self):
        expiry = self.contract["vendor_offer"]["listing"]["metadata"]["expiry"]
        if expiry == "never":
            return False
        elif datetime.strptime(expiry[:len(expiry)-4], '%Y-%m-%dT%H:%M') < datetime.utcnow():
            return True
        else:
            return False

    def delete(self, delete_images=False):
        """
        Deletes the contract json from the OpenBazaar directory as well as the listing
        metadata from the db and all the related images in the file system.
        """

        # get the file path
        file_path = self.db.filemap.get_file(self.contract["vendor_offer"]["listing"]["contract_id"])

        # maybe delete the images from disk
        if "image_hashes" in self.contract["vendor_offer"]["listing"]["item"] and delete_images:
            for image_hash in self.contract["vendor_offer"]["listing"]["item"]["image_hashes"]:
                # delete from disk
                image_path = self.db.filemap.get_file(image_hash)
                if os.path.exists(image_path):
                    os.remove(image_path)
                # remove pointer to the image from the filemap
                self.db.filemap.delete(image_hash)

        # delete the contract from disk
        if os.path.exists(file_path):
            os.remove(file_path)

        # delete the listing metadata from the db
        contract_hash = unhexlify(self.contract["vendor_offer"]["listing"]["contract_id"])
        self.db.listings.delete_listing(contract_hash)

        # remove the pointer to the contract from the filemap
        self.db.filemap.delete(contract_hash.encode("hex"))

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
        file_name += str(self.contract["vendor_offer"]["listing"]["contract_id"])[:8]

        # save the json contract to the file system
        file_path = os.path.join(DATA_FOLDER, "store", "contracts", "listings", file_name + ".json")
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))

        if self.previous_title and self.previous_title != self.contract["vendor_offer"]["listing"]["item"]["title"]:
            if isinstance(self.previous_title, unicode):
                self.previous_title = self.previous_title.encode('utf8')
            old_name = str(self.previous_title[:100])
            old_name = re.sub(r"[^\w\s]", '', file_name)
            old_name = re.sub(r"\s+", '_', file_name)
            old_name += str(self.contract["vendor_offer"]["listing"]["contract_id"])[:8]
            old_path = os.path.join(DATA_FOLDER, "store", "contracts", "listings", old_name + ".json")
            if os.path.exists(old_path):
                os.remove(old_path)

        # Create a `ListingMetadata` protobuf object using data from the full contract
        listings = Listings()
        data = listings.ListingMetadata()
        data.contract_hash = unhexlify(self.contract["vendor_offer"]["listing"]["contract_id"])
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
            data.price = round(float(vendor_item["price_per_unit"]["bitcoin"]), 8)
            data.currency_code = "BTC"
        data.nsfw = vendor_item["nsfw"]
        if "shipping" not in self.contract["vendor_offer"]["listing"]:
            data.origin = CountryCode.Value("NA")
        else:
            data.origin = CountryCode.Value(
                self.contract["vendor_offer"]["listing"]["shipping"]["shipping_origin"].upper())
            for region in self.contract["vendor_offer"]["listing"]["shipping"]["shipping_regions"]:
                data.ships_to.append(CountryCode.Value(region.upper()))
        if self.contract["vendor_offer"]["listing"]["metadata"]["category"].lower() == "physical good":
            data.contract_type = listings.PHYSICAL_GOOD
        elif self.contract["vendor_offer"]["listing"]["metadata"]["category"].lower() == "digital good":
            data.contract_type = listings.DIGITAL_GOOD
        elif self.contract["vendor_offer"]["listing"]["metadata"]["category"].lower() == "service":
            data.contract_type = listings.SERVICE
        data.last_modified = int(time.time())
        data.pinned = self.contract["vendor_offer"]["listing"]["metadata"]["pinned"]
        data.hidden = self.contract["vendor_offer"]["listing"]["metadata"]["hidden"]

        # save the mapping of the contract file path and contract hash in the database
        self.db.filemap.insert(data.contract_hash.encode("hex"), file_path[len(DATA_FOLDER):])

        # save the `ListingMetadata` protobuf to the database as well
        self.db.listings.add_listing(data)

    def process_refund(self, refund_json, blockchain, notification_listener):
        if "refund" in self.contract:
            raise Exception("Refund already processed for this order")
        self.contract["refund"] = refund_json["refund"]
        order_id = refund_json["refund"]["order_id"]

        if "txid" not in refund_json["refund"]:
            outpoints = json.loads(self.db.purchases.get_outpoint(order_id))
            refund_address = self.contract["buyer_order"]["order"]["refund_address"]
            redeem_script = self.contract["buyer_order"]["order"]["payment"]["redeem_script"]
            in_value = 0
            for outpoint in outpoints:
                in_value += outpoint["value"]
            out_value = in_value - long(self.contract["buyer_order"]["order"]["payment"]["refund_tx_fee"])
            tx = BitcoinTransaction.make_unsigned(outpoints, refund_address,
                                                  testnet=self.testnet,
                                                  out_value=out_value)
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_b = bitcointools.bip32_extract_key(KeyChain(self.db).bitcoin_master_privkey)
            buyer_priv = derive_childkey(masterkey_b, chaincode, bitcointools.MAINNET_PRIVATE)
            buyer_sigs = tx.create_signature(buyer_priv, redeem_script)
            vendor_sigs = refund_json["refund"]["signature(s)"]

            signatures = []
            for i in range(len(outpoints)):
                for vendor_sig in vendor_sigs:
                    if vendor_sig["index"] == i:
                        v_signature = vendor_sig["signature"]
                for buyer_sig in buyer_sigs:
                    if buyer_sig["index"] == i:
                        b_signature = buyer_sig["signature"]
                signature_obj = {"index": i, "signatures": [b_signature, v_signature]}
                signatures.append(signature_obj)

            tx.multisign(signatures, redeem_script)
            tx.broadcast(blockchain)
            self.db.transactions.add_transaction(tx.to_raw_tx())
            self.blockchain.unsubscribe_address(
                self.contract["buyer_order"]["order"]["payment"]["address"], self.on_tx_received)
            self.log.info("broadcasting refund tx %s to network" % tx.get_hash())

        self.db.purchases.update_status(order_id, 7)
        self.db.purchases.status_changed(order_id, 1)
        file_path = os.path.join(DATA_FOLDER, "purchases", "trade receipts", order_id + ".json")
        with open(file_path, 'w') as outfile:
            outfile.write(json.dumps(self.contract, indent=4))
        file_path = os.path.join(DATA_FOLDER, "purchases", "in progress", order_id + ".json")
        if os.path.exists(file_path):
            os.remove(file_path)

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
        notification_listener.notify(buyer_guid, handle, "refund", order_id, title, image_hash)

        notification = SMTPNotification(self.db)
        notification.send("[OpenBazaar] Refund Received", "You received a refund.<br><br>"
                                                          "Order: %s<br>Title: %s"
                          % (order_id, title))

    def verify(self, sender_key):
        """
        Validate that an order sent over by a buyer is filled out correctly.
        """
        SelectParams("testnet" if self.testnet else "mainnet")
        try:
            contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
            del contract_dict["buyer_order"]
            contract_hash = digest(json.dumps(contract_dict, indent=4))

            ref_hash = unhexlify(self.contract["buyer_order"]["order"]["ref_hash"])
            contract_id = self.contract["vendor_offer"]["listing"]["contract_id"]

            # verify that the reference hash matches the contract and that the contract actually exists
            if contract_hash != ref_hash or not self.db.filemap.get_file(contract_id):
                raise Exception("Order for contract that doesn't exist")

            # verify the vendor's own signature
            verify_key = self.keychain.signing_key.verify_key
            verify_key.verify(json.dumps(self.contract["vendor_offer"]["listing"], indent=4),
                              base64.b64decode(self.contract["vendor_offer"]["signatures"]["guid"]))

            # verify timestamp is within a reasonable time from now
            timestamp = self.contract["buyer_order"]["order"]["date"]
            dt = datetime.strptime(timestamp[:len(timestamp)-4], "%Y-%m-%d %H:%M:%S.%f")
            if abs((datetime.utcnow() - dt).total_seconds()) > 600:
                raise Exception("Timestamp on order not within 10 minutes of now")

            # verify the signatures on the order
            verify_obj = json.dumps(self.contract["buyer_order"]["order"], indent=4)

            verify_key = nacl.signing.VerifyKey(sender_key)
            verify_key.verify(verify_obj, base64.b64decode(self.contract["buyer_order"]["signatures"]["guid"]))

            bitcoin_key = self.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
            bitcoin_sig = self.contract["buyer_order"]["signatures"]["bitcoin"]
            valid = bitcointools.ecdsa_raw_verify(verify_obj, bitcointools.decode_sig(bitcoin_sig), bitcoin_key)
            if not valid:
                raise Exception("Invalid Bitcoin signature")

            # verify the quantity does not exceed the max
            quantity = int(self.contract["buyer_order"]["order"]["quantity"])
            if "max_quantity" in self.contract["vendor_offer"]["listing"]["metadata"]:
                if quantity > int(self.contract["vendor_offer"]["listing"]["metadata"]["max_quantity"]):
                    raise Exception("Buyer tried to purchase more than the max quantity")

            # verify buyer included the correct bitcoin amount for payment
            price_json = self.contract["vendor_offer"]["listing"]["item"]["price_per_unit"]
            if "bitcoin" in price_json:
                asking_price = float(price_json["bitcoin"]) * quantity
            else:
                currency_code = price_json["fiat"]["currency_code"]
                fiat_price = price_json["fiat"]["price"]

                conversion_rate = BtcPrice.instance().get(currency_code.upper())
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

                            conversion_rate = BtcPrice.instance().get(currency.upper(), False)
                            shipping_amount = float("{0:.8f}".format(float(price) /
                                                                     float(conversion_rate))) * quantity
                    else:
                        if "bitcoin" in self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]:
                            shipping_amount = float(self.contract["vendor_offer"]["listing"]["shipping"][
                                "flat_fee"]["bitcoin"]["international"]) * quantity
                        else:
                            price = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"]["fiat"][
                                "price"]["international"]
                            currency = self.contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][
                                "fiat"]["currency_code"]

                            conversion_rate = BtcPrice.instance().get(currency.upper(), False)
                            shipping_amount = float("{0:.8f}".format(float(price) /
                                                                     float(conversion_rate))) * quantity
                    asking_price += shipping_amount

            print round(float(asking_price), 8), float(self.contract["buyer_order"]["order"]["payment"]["amount"])
            if round(float(asking_price), 8) > float(self.contract["buyer_order"]["order"]["payment"]["amount"]):
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
                masterkey_v = bitcointools.bip32_extract_key(self.keychain.bitcoin_master_pubkey)
                buyer_key = unhexlify(derive_childkey(masterkey_b, chaincode))
                vendor_key = unhexlify(derive_childkey(masterkey_v, chaincode))
                moderator_key = unhexlify(derive_childkey(masterkey_m, chaincode))

                redeem_script = CScript([OP_2, buyer_key, vendor_key, moderator_key, OP_3, OP_CHECKMULTISIG])
                if redeem_script.encode("hex") != self.contract["buyer_order"]["order"]["payment"]["redeem_script"]:
                    raise Exception("Invalid redeem script")

                # verify the multisig payment address
                payment_address = str(P2SHBitcoinAddress.from_redeemScript(redeem_script))
                if payment_address != self.contract["buyer_order"]["order"]["payment"]["address"]:
                    raise Exception("Incorrect payment address")

            else:
                # verify the direct payment address
                chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
                masterkey_v = bitcointools.bip32_extract_key(self.keychain.bitcoin_master_pubkey)
                vendor_key = unhexlify(derive_childkey(masterkey_v, chaincode))

                # verify the payment address
                payment_address = str(P2PKHBitcoinAddress.from_pubkey(vendor_key))
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
            keys = ["guid", "bitcoin"]
            for value in map(pubkeys.get, keys):
                if value is None:
                    raise Exception("Missing pubkey field")

            return True

        except Exception, e:
            return e.message

    def validate_for_moderation(self, proof_sig):
        validation_failures = []

        tmp_contract = deepcopy(self.contract)
        if "buyer_order" in tmp_contract:
            del tmp_contract["buyer_order"]
        if "vendor_order_confirmation" in tmp_contract:
            del tmp_contract["vendor_order_confirmation"]
        if "buyer_receipt" in tmp_contract:
            del tmp_contract["buyer_receipt"]
        del tmp_contract["dispute"]

        contract_hash = digest(json.dumps(tmp_contract, indent=4))
        ref_hash = unhexlify(self.contract["buyer_order"]["order"]["ref_hash"])

        listing = json.dumps(self.contract["vendor_offer"]["listing"], indent=4)

        # verify that the reference hash matches the contract
        if contract_hash != ref_hash:
            validation_failures.append("Reference hash in buyer_order doesn't match the listing hash;")

        # validated the signatures on vendor_offer
        vendor_guid_signature = self.contract["vendor_offer"]["signatures"]["guid"]
        vendor_bitcoin_signature = self.contract["vendor_offer"]["signatures"]["bitcoin"]
        vendor_guid_pubkey = unhexlify(self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["guid"])
        vendor_bitcoin_pubkey = self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
        verify_key = nacl.signing.VerifyKey(vendor_guid_pubkey)
        try:
            verify_key.verify(listing, base64.b64decode(vendor_guid_signature))
        except Exception:
            validation_failures.append("Guid signature in vendor_offer not valid;")

        valid = bitcointools.ecdsa_raw_verify(listing,
                                              bitcointools.decode_sig(vendor_bitcoin_signature),
                                              vendor_bitcoin_pubkey)
        if not valid:
            validation_failures.append("Bitcoin signature in vendor_offer is not valid;")

        # verify the signatures on the order
        order = json.dumps(self.contract["buyer_order"]["order"], indent=4)
        buyer_guid_signature = self.contract["buyer_order"]["signatures"]["guid"]
        buyer_bitcoin_signature = self.contract["buyer_order"]["signatures"]["bitcoin"]
        buyer_bitcoin_pubkey = self.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
        buyer_guid_pubkey = unhexlify(self.contract["buyer_order"]["order"]["id"]["pubkeys"]["guid"])

        verify_key = nacl.signing.VerifyKey(buyer_guid_pubkey)
        try:
            verify_key.verify(order, base64.b64decode(buyer_guid_signature))
        except Exception:
            validation_failures.append("Guid signature in buyer_order not valid;")

        valid = bitcointools.ecdsa_raw_verify(order, bitcointools.decode_sig(buyer_bitcoin_signature),
                                              buyer_bitcoin_pubkey)
        if not valid:
            validation_failures.append("Bitcoin signature in buyer_order not valid;")

        # If the buyer filed this claim, check the vendor's signature to show he accepted the order.
        if proof_sig is not None:
            address = self.contract["buyer_order"]["order"]["payment"]["address"]
            chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
            masterkey_b = self.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
            buyer_key = derive_childkey(masterkey_b, chaincode)
            amount = self.contract["buyer_order"]["order"]["payment"]["amount"]
            listing_hash = self.contract["vendor_offer"]["listing"]["contract_id"]
            verify_key = nacl.signing.VerifyKey(vendor_guid_pubkey)
            try:
                verify_key.verify(str(address) + str(amount) + str(listing_hash) + str(buyer_key),
                                  base64.b64decode(proof_sig))
            except Exception:
                validation_failures.append("Vendor's order-acceptance signature not valid;")

        # verify redeem script
        chaincode = self.contract["buyer_order"]["order"]["payment"]["chaincode"]
        for mod in self.contract["vendor_offer"]["listing"]["moderators"]:
            if mod["guid"] == self.contract["buyer_order"]["order"]["moderator"]:
                masterkey_m = mod["pubkeys"]["bitcoin"]["key"]

        if masterkey_m != bitcointools.bip32_extract_key(self.keychain.bitcoin_master_pubkey):
            validation_failures.append("Moderator Bitcoin key doesn't match key in vendor_order;")

        masterkey_b = self.contract["buyer_order"]["order"]["id"]["pubkeys"]["bitcoin"]
        masterkey_v = self.contract["vendor_offer"]["listing"]["id"]["pubkeys"]["bitcoin"]
        buyer_key = derive_childkey(masterkey_b, chaincode)
        vendor_key = derive_childkey(masterkey_v, chaincode)
        moderator_key = derive_childkey(masterkey_m, chaincode)

        redeem_script = bitcointools.mk_multisig_script([buyer_key, vendor_key, moderator_key], 2)
        if redeem_script != self.contract["buyer_order"]["order"]["payment"]["redeem_script"]:
            validation_failures.append("Bitcoin redeem script not valid for the keys in this contract;")

        # verify address from redeem script
        if self.testnet:
            payment_address = bitcointools.p2sh_scriptaddr(redeem_script, 196)
        else:
            payment_address = bitcointools.p2sh_scriptaddr(redeem_script)
        if self.contract["buyer_order"]["order"]["payment"]["address"] != payment_address:
            validation_failures.append("Bitcoin address invalid. Cannot be derived from reddem script;")

        # validate vendor_order_confirmation
        if "vendor_order_confirmation" in self.contract:
            contract_dict = json.loads(json.dumps(self.contract, indent=4), object_pairs_hook=OrderedDict)
            del contract_dict["vendor_order_confirmation"]
            if "buyer_receipt" in contract_dict:
                del contract_dict["buyer_receipt"]
            contract_hash = digest(json.dumps(contract_dict, indent=4)).encode("hex")
            ref_hash = self.contract["vendor_order_confirmation"]["invoice"]["ref_hash"]
            if ref_hash != contract_hash:
                validation_failures.append("Reference hash in vendor_order_confirmation does not match order ID;")
            vendor_signature = self.contract["vendor_order_confirmation"]["signature"]
            confirmation = json.dumps(self.contract["vendor_order_confirmation"]["invoice"], indent=4)
            verify_key = nacl.signing.VerifyKey(vendor_guid_pubkey)
            try:
                verify_key.verify(confirmation, base64.b64decode(vendor_signature))
            except Exception:
                validation_failures.append("Vendor's signature in vendor_order_confirmation not valid;")

        # check the moderator fee is correct
        own_guid = self.keychain.guid.encode("hex")
        for moderator in self.contract["vendor_offer"]["listing"]["moderators"]:
            if moderator["guid"] == own_guid:
                fee = float(moderator["fee"][:len(moderator["fee"]) -1])
        if Profile(self.db).get().moderation_fee < fee:
            validation_failures.append("Moderator fee in contract less than current moderation fee;")

        return validation_failures

    def __repr__(self):
        return json.dumps(self.contract, indent=4)


def check_unfunded_for_payment(db, libbitcoin_client, notification_listener, testnet=False):
    """
    Run through the unfunded contracts in our database and query the
    libbitcoin server to see if they received a payment.
    """
    current_time = time.time()
    purchases = db.purchases.get_unfunded()
    for purchase in purchases:
        if current_time - purchase[1] <= 86400:
            check_order_for_payment(purchase[0], db, libbitcoin_client, notification_listener, testnet)
    sales = db.sales.get_unfunded()
    for sale in sales:
        if current_time - sale[1] <= 86400:
            check_order_for_payment(sale[0], db, libbitcoin_client, notification_listener, testnet)


def check_order_for_payment(order_id, db, libbitcoin_client, notification_listener, testnet=False):
    try:
        if os.path.exists(os.path.join(DATA_FOLDER, "purchases", "unfunded", order_id + ".json")):
            file_path = os.path.join(DATA_FOLDER, "purchases", "unfunded", order_id + ".json")
            is_purchase = True
        elif os.path.exists(os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", order_id + ".json")):
            file_path = os.path.join(DATA_FOLDER, "store", "contracts", "unfunded", order_id + ".json")
            is_purchase = False
        with open(file_path, 'r') as filename:
            order = json.load(filename, object_pairs_hook=OrderedDict)
        c = Contract(db, contract=order, testnet=testnet)
        c.blockchain = libbitcoin_client
        c.notification_listener = notification_listener
        c.is_purchase = is_purchase
        addr = c.contract["buyer_order"]["order"]["payment"]["address"]
        SelectParams("testnet" if testnet else "mainnet")
        script_pubkey = CBitcoinAddress(addr).to_scriptPubKey().encode("hex")

        def history_fetched(ec, history):
            if not ec:
                # pylint: disable=W0612
                # pylint: disable=W0640
                amount_funded = 0
                outpoints = []
                for objid, txhash, index, height, value in history:
                    amount_funded += value
                    o = {
                        "txid": txhash.encode("hex"),
                        "vout": index,
                        "value": value,
                        "scriptPubKey": script_pubkey
                    }
                    outpoints.append(o)

                # get the amount (in satoshi) the user is expected to pay
                amount_to_pay = int(float(c.contract["buyer_order"]["order"]["payment"]["amount"]) * 100000000)
                if amount_funded >= amount_to_pay:
                    c.outpoints = outpoints
                    c.payment_received()

        libbitcoin_client.fetch_history2(addr, history_fetched)
    except Exception:
        pass
