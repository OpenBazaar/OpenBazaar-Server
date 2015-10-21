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
    if fc.has_section(mySection):

        # Extract Config DATA_FOLDER
        data_f2 = ''
        nameOptionDF = 'DATA_FOLDER'

        # if exist option in file config
        if fc.has_option(mySection, nameOptionDF):
            optionDataFolder = fc.get(mySection, nameOptionDF)
            # if have a value
            if optionDataFolder:
                data_f1 = join(dataFolderPath, optionDataFolder)
                data_f2 = join(data_f1, '')  # is necesary for "/" the end
        else:
            print 'No Found option "{0}"'.format(nameOptionDF)

        # Extract Config SEED_NODE
        seed_n = ''
        seed_n_p = ''
        nameOptionSN = 'SEED_NODE'

        if fc.has_option(mySection, nameOptionSN):
            optionSeedNode = fc.get(mySection, nameOptionSN)
            # if have value
            if optionSeedNode:
                if ':' in fc.get(mySection, nameOptionSN):
                    seed_n = fc.get(mySection, nameOptionSN).split(':')[0]
                    seed_n_p = int(fc.get(mySection, nameOptionSN).split(':')[1])
        else:
            print 'No Found option "{0}"'.format(nameOptionSN)

        # Extract Config SEED_NODE_TESTNET
        seed_n_t = ''
        seed_n_t_p = ''
        nameOptionSNT = 'SEED_NODE_TESTNET'

        if fc.has_option(mySection, nameOptionSNT):
            optionSeeNodeTest = fc.get(mySection, nameOptionSNT)
            # if have value
            if optionSeeNodeTest:
                if ':' in fc.get(mySection, nameOptionSNT):
                    seed_n_t = fc.get(mySection, nameOptionSNT).split(':')[0]
                    seed_n_t_p = int(fc.get(mySection, nameOptionSNT).split(':')[1])
        else:
            print 'No Found option "{0}"'.format(nameOptionSNT)

        # Extract Config KSIZE
        ks = ''
        nameOptionKS = 'KSIZE'

        if fc.has_option(mySection, nameOptionKS):
            optionKSize = fc.getint(mySection, nameOptionKS)
            # if have value
            ks = '' if not optionKSize else optionKSize
        else:
            print 'No Found option "{0}"'.format(nameOptionKS)

        # extract Config APLHA
        alp = ''
        nameOptionAlpha = 'ALPHA'
        if fc.has_option(mySection, nameOptionAlpha):
            optionAlpha = fc.getint(mySection, nameOptionAlpha)
            # if have value
            alp = '' if not optionAlpha else optionAlpha
        else:
            print 'No Found option "{0}"'.format(nameOptionAlpha)

        # extract Config  TRANSACTION_FEE
        trans_f = ''
        nameOptionTrans_f = 'TRANSACTION_FEE'
        if fc.has_option(mySection, nameOptionTrans_f):
            optionTrans_f = fc.getint(mySection, nameOptionTrans_f)
            # if have value
            trans_f = '' if not optionTrans_f else optionTrans_f
        else:
            print 'No Found option "{0}"'.format(nameOptionTrans_f)

        DATA_FOLDER = data_f2
        SEED_NODE = (seed_n, seed_n_p)
        SEED_NODE_TESTNET = (seed_n_t, seed_n_t_p)
        KSIZE = ks
        ALPHA = alp
        TRANSACTION_FEE = trans_f
    else:
        message = 'No Section name "{0}" in file config:{1}'.format(mySection, myFileConfig)
        print message
else:
    message = 'The file Config "{0}" not found'.format(finalFileConfig)
    print message
