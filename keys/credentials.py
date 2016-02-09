import base64
import random
from config import USERNAME, PASSWORD
from hashlib import sha256


def get_credentials(database):
    settings = database.Settings()
    creds = settings.get_credentials()
    if creds == (USERNAME, PASSWORD):
        return creds
    elif creds is not None and (USERNAME is None or PASSWORD is None):
        return creds
    elif creds is not None and USERNAME is not None and PASSWORD is not None:
        settings.set_credentials(USERNAME, PASSWORD)
        return (USERNAME, PASSWORD)
    elif creds is None and (USERNAME is None or PASSWORD is None):
        username = base64.b64encode(sha256(str(random.getrandbits(255))).digest())
        password = base64.b64encode(sha256(str(random.getrandbits(255))).digest())
        settings.set_credentials(username, password)
        return (username, password)
    elif creds is None and (USERNAME is not None and PASSWORD is not None):
        settings.set_credentials(USERNAME, PASSWORD)
        return (USERNAME, PASSWORD)
