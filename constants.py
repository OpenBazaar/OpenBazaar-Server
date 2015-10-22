__author__ = 'foxcarlos'
from os import getcwd
from os.path import expanduser, join, isfile
import ConfigParser

dataFolderPath = expanduser('~')
currentPath = getcwd()
myFileConfig = 'ob.cfg'
finalFileConfig = join(currentPath, myFileConfig)
fc = ConfigParser.ConfigParser(allow_no_value=True)

# if file config found
if isfile(finalFileConfig):
    fc.read(finalFileConfig)

    # name of section in Config File ob.cfg
    mySection = 'CONSTANTS'

    # if exist the sections in file config
    try:
        # Extract Config DATA_FOLDER
        data_f2 = ''
        nameOptionDF = 'DATA_FOLDER'

        # if exist option in file config
        # if fc.has_option(mySection, nameOptionDF):
        try:
            optionDataFolder = fc.get(mySection, nameOptionDF)
            # if have a value
            if optionDataFolder:
                data_f1 = join(dataFolderPath, optionDataFolder)
                data_f2 = join(data_f1, '')  # is necesary for put "/" the end
        except ConfigParser.Error, error:
            print error

        # Extract Config SEED_NODE
        seed_n = ''
        seed_n_p = ''
        nameOptionSN = 'SEED_NODE'

        #if fc.has_option(mySection, nameOptionSN):
        try:
            optionSeedNode = fc.get(mySection, nameOptionSN)
            # if have value
            if optionSeedNode:
                if ':' in fc.get(mySection, nameOptionSN):
                    seed_n = fc.get(mySection, nameOptionSN).split(':')[0]
                    try:
                        seed_n_p = int(fc.get(mySection, nameOptionSN).split(':')[1])
                    except ValueError, error:
                        print error
        except ConfigParser.Error, error:
            print error

        # Extract Config SEED_NODE_TESTNET
        seed_n_t = ''
        seed_n_t_p = ''
        nameOptionSNT = 'SEED_NODE_TESTNET'

        #if fc.has_option(mySection, nameOptionSNT):
        try:
            optionSeeNodeTest = fc.get(mySection, nameOptionSNT)
            # if have value
            if optionSeeNodeTest:
                if ':' in fc.get(mySection, nameOptionSNT):
                    seed_n_t = fc.get(mySection, nameOptionSNT).split(':')[0]
                    try:
                        seed_n_t_p = int(fc.get(mySection, nameOptionSNT).split(':')[1])
                    except ValueError, error:
                        print error
        except ConfigParser.Error, error:
            print error

        # Extract Config KSIZE
        ks = ''
        nameOptionKS = 'KSIZE'

        #if fc.has_option(mySection, nameOptionKS):
        try:
            optionKSize = fc.get(mySection, nameOptionKS)
            # if have value
            try:
                ks = '' if not optionKSize else int(optionKSize)
            except ValueError, error:
                print error

        except ConfigParser.Error, error:
            print error

        # extract Config APLHA
        alp = ''
        nameOptionAlpha = 'ALPHA'

        #if fc.has_option(mySection, nameOptionAlpha):
        try:
            optionAlpha = fc.get(mySection, nameOptionAlpha)
            # if have value
            try:
                alp = '' if not optionAlpha else int(optionAlpha)
            except ValueError, error:
                print error

        except ConfigParser.Error, error:
            print error

        # extract Config  TRANSACTION_FEE
        trans_f = ''
        nameOptionTrans_f = 'TRANSACTION_FEE'

        #if fc.has_option(mySection, nameOptionTrans_f):
        try:
            optionTrans_f = fc.get(mySection, nameOptionTrans_f)
            # if have value
            try:
                trans_f = '' if not optionTrans_f else int(optionTrans_f)
            except ValueError, error:
                print error

        except ConfigParser.Error, error:
            print error

        DATA_FOLDER = data_f2
        SEED_NODE = (seed_n, seed_n_p)
        SEED_NODE_TESTNET = (seed_n_t, seed_n_t_p)
        KSIZE = ks
        ALPHA = alp
        TRANSACTION_FEE = trans_f
    except ConfigParser.Error, error:
        print error
else:
    message = 'The file Config "{0}" not found'.format(finalFileConfig)
    print message
