import os
from os.path import expanduser

DATA_FOLDER = expanduser("~") + "/OpenBazaar/"
DATABASE = DATA_FOLDER + "OB.db"
if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)