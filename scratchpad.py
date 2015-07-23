__author__ = 'chris'
from constants import DATA_FOLDER
from binascii import hexlify, unhexlify
from dht.utils import digest
import os.path

image_hash = unhexlify("fde22bb225dccc858ea13cf485c608bac8faa0a7")

def getImage():
    try:
        with open(DATA_FOLDER + "store/media/" + hexlify(image_hash), "r") as file:
            file = file.read()
            print digest(file).encode("hex")
            if not os.path.isfile(DATA_FOLDER + "cache/" + digest(file).encode("hex")):
                with open(DATA_FOLDER + "cache/" + digest(file).encode("hex"), 'w') as outfile:
                    outfile.write(file)
        return [file]
    except:
        return ["None"]

print getImage()