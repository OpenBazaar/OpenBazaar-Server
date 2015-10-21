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
            print('No Found option "{0}"'.format(nameOptionDF))

        if ':' in fc.get(mySection, 'SEED_NODE'):
            seed_n = fc.get(mySection, 'SEED_NODE').split(':')[0]
            seed_n_p = int(fc.get(mySection, 'SEED_NODE').split(':')[1])

        if ':' in fc.get(mySection, 'SEED_NODE_TESTNET'):
            seed_n_t = fc.get(mySection, 'SEED_NODE_TESTNET').split(':')[0]
            seed_n_t_p = int(fc.get(mySection, 'SEED_NODE_TESTNET').split(':')[1])

        ks = fc.getint(mySection, 'KSIZE')
        alp = fc.getint(mySection, 'ALPHA')
        trans_f = fc.getint(mySection, 'TRANSACTION_FEE')

        DATA_FOLDER = data_f2
        SEED_NODE = (seed_n, seed_n_p)
        SEED_NODE_TESTNET = (seed_n_t, seed_n_t_p)
        KSIZE = ks
        ALPHA = alp
        TRANSACTION_FEE = trans_f
    else:
        message = 'No Section name "{0}" in file config:{1}'.format(mySection, myFileConfig)
        print(message)
else:
    message = 'The file Config "{0}" not found'.format(finalFileConfig)
    print(message)
