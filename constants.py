from os import getcwdu
from os.path import expanduser, join
import ConfigParser

dataFolderPath = expanduser('~')
currentPath = getcwdu()
myFileConfig = 'ob.cfg'
finalFileConfig = join(currentPath, myFileConfig)
fc = ConfigParser.ConfigParser(allow_no_value=True)
fc.read(finalFileConfig)

#name of section in Config File ob.cfg
mySection = 'CONSTANTS'

#if exist the sections in file config
if fc.has_section(mySection):
    #capture info
    data_f = join(currentPath, fc.get(mySection, 'DATA_FOLDER'))
    seed_n = fc.get(mySection, 'SEED_NODE')
    seed_n_p = fc.getint(mySection, 'SEED_NODE_PORT')
    seed_n_t = fc.get(mySection, 'SEED_NODE_TESTNET')
    seed_n_t_p = fc.getint(mySection, 'SEED_NODE_TESTNET_PORT')
    ks = fc.getint(mySection, 'KSIZE')
    alp = fc.getint(mySection, 'ALPHA' )
    trans_f  = fc.getint(mySection, 'TRANSACTION_FEE')

    DATA_FOLDER = data_f
    SEED_NODE = (seed_n, seed_n_p)
    SEED_NODE_TESTNET = (seed_n_t, seed_n_t_p)
    KSIZE = ks
    ALPHA = alp
    TRANSACTION_FEE = trans_f

'''
from os.path import expanduser

# TODO: this can be loaded from a config file

DATA_FOLDER = expanduser("~") + "/OpenBazaar/"
SEED_NODE = ("205.186.154.163", 18467)
SEED_NODE_TESTNET = ("205.186.154.163", 28467)
KSIZE = 20
ALPHA = 3
TRANSACTION_FEE = 10000'''

