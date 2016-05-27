__author__ = 'hoffmabc'

from log import Logger


class Audit(object):
    """
    A class for handling audit information
    """

    def __init__(self, db):
        self.db = db

        self.log = Logger(system=self)

        self.action_ids = {
            "GET_PROFILE": 0,
            "GET_CONTRACT": 1,
            "GET_LISTINGS": 2,  # Click Store tab
            "GET_FOLLOWING": 3,
            "GET_FOLLOWERS": 4,
            "GET_RATINGS": 5
        }

    def record(self, guid, action_id, contract_hash=None):
        self.log.info("Recording Audit Event [%s]" % action_id)

        if action_id in self.action_ids:
            self.db.audit_shopping.set(guid, self.action_ids[action_id], contract_hash)
        else:
            self.log.error("Could not identify this action id")
