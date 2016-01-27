__author__ = 'chris'

import json
import urllib2
from constants import RESOLVER


def resolve(blockchain_id):
    """
    Given a blockchain id return the corresponding GUID. The resolver
    url can be set in the config file. The resolver is open source so
    you can run your own if you want the full decentralized experience.
    """
    if blockchain_id[:1] == "@":
        blockchain_id = blockchain_id[1:]

    try:
        data = json.load(urllib2.urlopen(RESOLVER + 'v2/users/' + blockchain_id))
        for account in data[blockchain_id]["profile"]["account"]:
            if account["service"] == "openbazaar":
                return account["identifier"]
    except (urllib2.HTTPError, KeyError, TypeError):
        return None


def validate(blockchain_id, guid):
    """Does the blockchain_id resolve to the given guid"""
    return resolve(blockchain_id) == guid
