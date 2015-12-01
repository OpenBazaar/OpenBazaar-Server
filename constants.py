__author__ = 'foxcarlos-TeamCreed'
from os import getcwd
from os.path import expanduser, join, isfile
import ConfigParser

PROTOCOL_VERSION = 5

dataFolderPath = expanduser('~')
currentPath = getcwd()
myFileConfig = 'ob.cfg'
finalFileConfig = join(currentPath, myFileConfig)
fc = ConfigParser.ConfigParser(allow_no_value=True)

# if file config not found
if not isfile(finalFileConfig):
    message = 'The file Config "{0}" not found'.format(finalFileConfig)
    print message
else:
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

        try:
            optionTrans_f = fc.get(mySection, nameOptionTrans_f)
            # if have value
            try:
                trans_f = '' if not optionTrans_f else int(optionTrans_f)
            except ValueError, error:
                print error

        except ConfigParser.Error, error:
            print error

        # Extract Config LIBBITCOIN_SERVER
        libbitcoin_s = ''
        nameOptionLBS = 'LIBBITCOIN_SERVER'

        try:
            optionLBS = fc.get(mySection, nameOptionLBS)
            # if have value
            if optionLBS:
                libbitcoin_s = optionLBS
        except ConfigParser.Error, error:
            print error

        # Extract Config LIBBITCOIN_SERVER_TESTNET
        libbitcoin_s_t = ''
        nameOptionLBS_T = 'LIBBITCOIN_SERVER_TESTNET'

        try:
            optionLBS_T = fc.get(mySection, nameOptionLBS_T)
            # if have value
            if optionLBS_T:
                libbitcoin_s_t = optionLBS_T
        except ConfigParser.Error, error:
            print error

        # extract Config  SSL_CERT
        ssl_crt = ''
        nameOptionSsl_crt = 'SSL_CERT'

        try:
            optionssl_crt = fc.get(mySection, nameOptionSsl_crt)
            # if have value
            try:
                ssl_crt = '' if not optionssl_crt else optionssl_crt
            except ValueError, error:
                print error

        except ConfigParser.Error, error:
            pass

        # extract Config  SSL_KEY
        ssl_key = ''
        nameOptionSsl_key = 'SSL_KEY'
        try:
            optionssl_key = fc.get(mySection, nameOptionSsl_key)
            # if have value
            try:
                ssl_key = '' if not optionssl_key else optionssl_key
            except ValueError, error:
                print error

        except ConfigParser.Error, error:
            pass

        # Extract Config SEEDS
        mySection_2 = 'SEEDS'
        seed = ''
        lSeed = []
        goodSeeds = []
        logError = 'Wrong config file "{0}", this value is ignored'

        if fc.has_section(mySection_2):
            try:
                listSeed = [seeds[1] for seeds in fc.items(mySection_2)]
                lSeed = [tuple(s.split(",")) for s in listSeed]
            except ConfigParser.Error, error:
                print error

            for s in lSeed:
                errorInSeed = True
                if len(s) == 2:
                    seed, key = s
                    if ':' in seed:
                        url, port = seed.split(':')
                        if url and port:
                            if key:
                                goodSeeds.append(s)
                                errorInSeed = False
                if errorInSeed:
                    print logError.format(s)
        else:
            print 'No SECTIONS "{0}" in fileConfig ob.cfg'.format(mySection_2)

        # Constant Assignment
        DATA_FOLDER = data_f2
        SEED_NODE = (seed_n, seed_n_p)
        SEED_NODE_TESTNET = (seed_n_t, seed_n_t_p)
        KSIZE = ks
        ALPHA = alp
        TRANSACTION_FEE = trans_f
        LIBBITCOIN_SERVER = libbitcoin_s
        LIBBITCOIN_SERVER_TESTNET = libbitcoin_s_t
        SSL_CERT = ssl_crt
        SSL_KEY = ssl_key
        SEED = goodSeeds

    except ConfigParser.Error, error:
        print error
