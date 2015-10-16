from os import getcwdu
from os.path import expanduser, join
import ConfigParser

dataFolderPath = expanduser('~')
currentPath = getcwdu()
myFileConfig = 'constants.cfg'
finalFileConfig = join(currentPath, myFileConfig)

fc = ConfigParser.ConfigParser()
fc.read(finalFileConfig)

mySection = 'CONSTANTS'

if fc.has_section(mySection):
    items = fc.items(mySection)
    values = [value[1] for value in items]

    data_folder, seed_node, seed_node_testnet, ksize, alpha, trans_fee = values

    DATA_FOLDER = values[0]
    SEED_NODE = values[1]
    SEED_NODE_TESTNET = values[2]
    KSIZE = values[3]
    ALPHA = values[4]
    TRANSACTION_FEE = values[5]

'''
DATA_FOLDER = expanduser("~") + "/OpenBazaar/"
SEED_NODE = ("205.186.154.163", 18467)
SEED_NODE_TESTNET = ("205.186.154.163", 28467)
KSIZE = 20
ALPHA = 3
TRANSACTION_FEE = 10000'''

'''from os.path import expanduser

# TODO: this can be loaded from a config file

DATA_FOLDER = expanduser("~") + "/OpenBazaar/"
SEED_NODE = ("205.186.154.163", 18467)
SEED_NODE_TESTNET = ("205.186.154.163", 28467)
KSIZE = 20
ALPHA = 3
TRANSACTION_FEE = 10000'''

