import os
from os.path import expanduser

DATA_FOLDER = expanduser("~") + "/OpenBazaar"
if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)