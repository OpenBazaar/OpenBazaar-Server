import os
from os.path import expanduser

# This should be turned into a more formal context module

DATA_FOLDER = expanduser("~") + "/OpenBazaar/"
DATABASE = DATA_FOLDER + "OB.db"
SEED_NODE = ("162.213.253.147", 18467)
if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)
