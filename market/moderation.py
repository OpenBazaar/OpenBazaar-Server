import json
import nacl.signing
import time
from binascii import unhexlify
from dht.utils import digest
from keyutils.keys import KeyChain
from market.contracts import Contract
from protos.objects import PlaintextMessage


def process_dispute(contract, db, message_listener, notification_listener, testnet):
    """
    This function processes a dispute message received from another node. It checks the
    contract to see if this a dispute for a purchase we made, a dispute for one of our
    sales, or a new case if we are the moderator.

    If it's a purchase or sale it will
    update the order status to disputed and push a notification to the listener.

    If it's a new case it will validate the contract, create a new case in the db,
    and push a notification to the listener.

    Args:
        contract: a json contract of the current order state. Should have a "dispute"
            object attached with dispute info.
        db: a `Database` object.
        message_listener: a `MessageListenerImpl` object.
        notification_listener: a `NotificationListenerImpl` object.
        testnet: `bool` of whether we're on testnet or not.

    Returns: a `List` of `String` validation failures, if any.

    """

    if "vendor_order_confirmation" in contract:
        del contract["vendor_order_confirmation"]
    if "buyer_receipt" in contract:
        del contract["buyer_receipt"]

    order_id = digest(json.dumps(contract, indent=4)).encode("hex")
    own_guid = KeyChain(db).guid.encode("hex")

    if contract["dispute"]["guid"] == contract["vendor_offer"]["listing"]["id"]["guid"]:
        guid = unhexlify(contract["vendor_offer"]["listing"]["id"]["guid"])
        signing_key = unhexlify(contract["vendor_offer"]["listing"]["id"]["pubkeys"]["guid"])
        if "blockchain_id" in contract["vendor_offer"]["listing"]["id"]:
            handle = contract["vendor_offer"]["listing"]["id"]["blockchain_id"]
        else:
            handle = ""
        encryption_key = unhexlify(contract["vendor_offer"]["listing"]["id"]["pubkeys"]["encryption"])
        proof_sig = contract["dispute"]["proof_sig"]
    elif contract["dispute"]["guid"] == contract["buyer_order"]["order"]["id"]["guid"]:
        guid = unhexlify(contract["buyer_order"]["order"]["id"]["guid"])
        signing_key = unhexlify(contract["buyer_order"]["order"]["id"]["pubkeys"]["guid"])
        if "blockchain_id" in contract["buyer_order"]["order"]["id"]:
            handle = contract["buyer_order"]["order"]["id"]["blockchain_id"]
        else:
            handle = ""
        encryption_key = unhexlify(contract["buyer_order"]["order"]["id"]["pubkeys"]["encryption"])
        proof_sig = None
    else:
        raise Exception("Dispute guid not in contract")

    verify_key = nacl.signing.VerifyKey(signing_key)
    verify_key.verify(contract["dispute"]["claim"], contract["dispute"]["signature"])

    p = PlaintextMessage()
    p.sender_guid = guid
    p.handle = handle
    p.signed_pubkey = signing_key
    p.encryption_pubkey = encryption_key
    p.subject = order_id
    p.type = PlaintextMessage.Type.Value("DISPUTE")
    p.message = contract["dispute"]["claim"]
    p.timestamp = time.time()
    p.avatar_hash = contract["dispute"]["avatar_hash"]

    if db.Purchases().get_purchase(order_id) is not None:
        db.Purchases().update_status(order_id, 4)

    elif db.Sales().get_sale(order_id) is not None:
        db.Purchases().update_status(order_id, 4)

    elif "moderators" in contract["vendor_offer"]["listing"]:
        is_selected = False
        for moderator in contract["vendor_offer"]["listing"]["moderators"]:
            if moderator["guid"] == own_guid and contract["buyer_order"]["order"]["moderator"] == own_guid:
                is_selected = True
        if not is_selected:
            raise Exception("Not a moderator for this contract")
        else:
            if "blockchain_id" in contract["vendor_offer"]["listing"]["id"]:
                vendor = contract["vendor_offer"]["listing"]["id"]["blockchain_id"]
            else:
                vendor = contract["vendor_offer"]["listing"]["id"]["guid"]
            if "blockchain_id" in contract["buyer_order"]["order"]["id"]:
                buyer = contract["buyer_order"]["order"]["id"]["blockchain_id"]
            else:
                buyer = contract["buyer_order"]["order"]["id"]["guid"]

            c = Contract(db, contract=contract, testnet=testnet)

            validation_failures = c.validate_for_moderation(proof_sig)

            db.Cases().new_case(order_id,
                                contract["vendor_offer"]["listing"]["item"]["title"],
                                time.time(),
                                contract["buyer_order"]["order"]["date"],
                                contract["buyer_order"]["order"],
                                float(contract["buyer_order"]["order"]["payment"]["amount"]),
                                contract["vendor_offer"]["listing"]["item"]["image_hashes"][0],
                                buyer, vendor, json.dumps(validation_failures))
    else:
        raise Exception("Order ID for dispute not found")

    message_listener.notify(p, "")
    notification_listener.notify(guid, handle, "dispute", order_id,
                                 contract["vendor_offer"]["listing"]["item"]["title"],
                                 contract["vendor_offer"]["listing"]["item"]["image_hashes"][0])
