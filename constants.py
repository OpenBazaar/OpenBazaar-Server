from os import getcwdu
from os.path import expanduser, join
import ConfigParser

dataFolderPath = expanduser('~')
currentPath = getcwdu()
myFileConfig = 'ob.cfg'
finalFileConfig = join(currentPath, myFileConfig)
fc = ConfigParser.ConfigParser()
fc.read(finalFileConfig)

mySection = 'CONSTANTS'

if fc.has_section(mySection):
    items = fc.items(mySection)
    values = [value[1] for value in items]

    data_f, seed_n, seed_n_p, seed_n_t, seed_n_t_p, ks, alp, trans_f = values

    DATA_FOLDER = data_f
    SEED_NODE = (seed_n, seed_n_p)
    SEED_NODE_TESTNET = (seed_n_t, seed_n_t_p)
    KSIZE = ks
    ALPHA = alp
    TRANSACTION_FEE = trans_f

    print DATA_FOLDER
    print SEED_NODE
    print SEED_NODE_TESTNET
    print KSIZE
    print ALPHA
    print TRANSACTION_FEE


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

