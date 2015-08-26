import os
from os.path import expanduser

# This should be turned into a more formal context module

DATA_FOLDER = expanduser("~") + "/OpenBazaar/"
DATABASE = DATA_FOLDER + "OB.db"
SEED_NODE = ("162.213.253.147", 18467)
if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER + "cache/")
    os.makedirs(DATA_FOLDER + "store/listings/contracts/")
    os.makedirs(DATA_FOLDER + "store/listings/in progress/")
    os.makedirs(DATA_FOLDER + "store/listings/trade receipts/")
    os.makedirs(DATA_FOLDER + "store/media/")
