'''Parses configuration file and sets project wide constants.
This file has intrinsic naming difficulties because it is trying to be platform
agnostic but naming variables is inherently platform specific (i.e directory vs
folder)
'''
__author__ = 'foxcarlos-TeamCreed', 'Tobin Harding'

import os
from random import shuffle
from platform import platform
from os.path import expanduser, join, isfile
from ConfigParser import ConfigParser
from urlparse import urlparse

PROTOCOL_VERSION = 1
CONFIG_FILE = join(os.getcwd(), 'ob.cfg')

# FIXME probably a better way to do this. This curretly checks two levels deep.
for i in range(2):
    if not isfile(CONFIG_FILE):
        paths = CONFIG_FILE.rsplit('/', 2)
        CONFIG_FILE = join(paths[0], paths[2])

DEFAULTS = {
    # Default project config file may now remove these items
    'data_folder': None,
    'ksize': '20',
    'alpha': '3',
    'transaction_fee': '10000',
    'libbitcoin_servers': 'tcp://libbitcoin1.openbazaar.org:9091',
    'libbitcoin_servers_testnet': 'tcp://libbitcoin2.openbazaar.org:9091, <Z&{.=LJSPySefIKgCu99w.L%b^6VvuVp0+pbnOM',
    'resolver': 'http://resolver.onename.com/',
    'ssl_cert': None,
    'ssl_key': None,
    'ssl': False,
    'username': None,
    'password': None,
    'mainnet_seeds': 'seed2.openbazaar.org:8080,8b17082a57d648894a5181cb6e1b8a6f5b3b7e1c347c0671abfcd7deb6f105fe',
    'testnet_seeds': 'seed.openbazaar.org:8080,5b44be5c18ced1bc9400fe5e79c8ab90204f06bebacc04dd9c70a95eaca6e117',

}


def str_to_bool(s):
    if isinstance(s, bool):
        return s
    if s.lower() == 'true':
        return True
    elif s.lower() == 'false':
        return False
    else:
        raise ValueError


def _platform_agnostic_data_path(data_folder):
    '''
    Create absolute path name, exported as DATA_FOLDER.
    User may configure using relative path, absolute path or use default.
      Relative path puts named folder in users home directory.
      Absolute path uses (obviously) the named absolute path.
      Default is currently to use 'OpenBazaar' in home directory.
    See issue #163
    '''
    if data_folder:
        if os.path.isabs(data_folder):
            return data_folder

    return join(_platform_agnostic_home_path(), _platform_agnostic_data_folder(data_folder), '')


def _platform_agnostic_home_path():
    home_path = ''
    if _is_windows():
        home_path = os.environ['HOMEPATH'] # Does this work for versions before Windows 7?
    else:
        home_path = expanduser('~')

    return home_path


# see issue  #163
def _platform_agnostic_data_folder(data_folder):
    '''
    Try to fit in with platform file naming conventions.
    '''
    if data_folder:
        return data_folder

    name = ''
    if _is_osx():
        name = join('Library', 'Application Support', 'OpenBazaar')
    elif _is_linux():
        name = '.openbazaar'
    else:
        name = join(os.getenv('APPDATA'), 'OpenBazaar')

    return name


def _is_windows():
    which_os = platform(aliased=True, terse=True).lower()
    return 'window' in which_os


def _is_linux():
    which_os = platform(aliased=True, terse=True).lower()
    return 'linux' in which_os


def _is_osx():
    which_os = platform(aliased=True, terse=True).lower()
    return 'darwin' in which_os


def _is_well_formed_seed_string(string):
    '''
    Parse string url:port,key
    '''
    if ',' in string:
        url, key = string.split(',')
        parsed = urlparse(url)
        if _validate_url(parsed.geturl()):
            if _validate_key(key):
                return True

    return False


def _validate_url(url):
    # TODO (How tight should the configuration requirements for a url be?)
    return True


def _validate_key(key):
    # TODO (is this done elsewhere in the project?)
    return True


def _is_tuple(tup, key):
    if isinstance(tup, tuple):
        return key in tup[0]

    return False


def _tuple_from_string(string):
    '''
    Accepts well formed seed string, returns tuple (url:port, key)
    '''
    l = string.split(',')
    if len(l) == 1:
        l.append(None)
    return tuple(l)


cfg = ConfigParser(DEFAULTS)

if isfile(CONFIG_FILE):
    cfg.read(CONFIG_FILE)
else:
    print 'Warning: configuration file not found: (%s), using default values' % CONFIG_FILE

DATA_FOLDER = _platform_agnostic_data_path(cfg.get('CONSTANTS', 'DATA_FOLDER'))
KSIZE = int(cfg.get('CONSTANTS', 'KSIZE'))
ALPHA = int(cfg.get('CONSTANTS', 'ALPHA'))
TRANSACTION_FEE = int(cfg.get('CONSTANTS', 'TRANSACTION_FEE'))
RESOLVER = cfg.get('CONSTANTS', 'RESOLVER')
SSL = str_to_bool(cfg.get('AUTHENTICATION', 'SSL'))
SSL_CERT = cfg.get('AUTHENTICATION', 'SSL_CERT')
SSL_KEY = cfg.get('AUTHENTICATION', 'SSL_KEY')
USERNAME = cfg.get('AUTHENTICATION', 'USERNAME')
PASSWORD = cfg.get('AUTHENTICATION', 'PASSWORD')
LIBBITCOIN_SERVERS = []
LIBBITCOIN_SERVERS_TESTNET = []
SEEDS = []
SEEDS_TESTNET = []

items = cfg.items('MAINNET_SEEDS')  # this also includes items in DEFAULTS
for item in items:
    if _is_tuple(item, "mainnet_seed"):
        seed = item[1]
        if _is_well_formed_seed_string(seed):
            new_seed = _tuple_from_string(seed)
            if new_seed not in SEEDS:
                SEEDS.append(new_seed)
        else:
            print 'Warning: please check your configuration file: %s' % seed

items = cfg.items('TESTNET_SEEDS')  # this also includes items in DEFAULTS
for item in items:
    if _is_tuple(item, "testnet_seed"):
        seed = item[1]
        if _is_well_formed_seed_string(seed):
            new_seed = _tuple_from_string(seed)
            if new_seed not in SEEDS_TESTNET:
                SEEDS_TESTNET.append(new_seed)
        else:
            print 'Warning: please check your configuration file: %s' % seed

items = cfg.items('LIBBITCOIN_SERVERS')  # this also includes items in DEFAULTS
for item in items:
    if _is_tuple(item, "mainnet_server"):
        server = item[1]
        new_server = _tuple_from_string(server)
        if item[0] == "mainnet_server_custom":
            LIBBITCOIN_SERVERS = [new_server]
            break
        elif new_server not in LIBBITCOIN_SERVERS:
            LIBBITCOIN_SERVERS.append(new_server)
        else:
            print 'Warning: please check your configuration file: %s' % server
shuffle(LIBBITCOIN_SERVERS)

items = cfg.items('LIBBITCOIN_SERVERS_TESTNET')  # this also includes items in DEFAULTS
for item in items:
    if _is_tuple(item, "testnet_server"):
        server = item[1]
        new_server = _tuple_from_string(server)
        if item[0] == "testnet_server_custom":
            LIBBITCOIN_SERVERS_TESTNET = [new_server]
            break
        elif new_server not in LIBBITCOIN_SERVERS_TESTNET:
            LIBBITCOIN_SERVERS_TESTNET.append(new_server)
        else:
            print 'Warning: please check your configuration file: %s' % server
shuffle(LIBBITCOIN_SERVERS_TESTNET)


def set_value(section, name, value):
    config = ConfigParser()
    if isfile(CONFIG_FILE):
        config.read(CONFIG_FILE)
    config.set(section, name, value)
    with open(CONFIG_FILE, 'wb') as configfile:
        config.write(configfile)


def get_value(section, name):
    config = ConfigParser()
    if isfile(CONFIG_FILE):
        config.read(CONFIG_FILE)
        try:
            return config.get(section, name)
        except Exception:
            return None


def delete_value(section, name):
    config = ConfigParser()
    if isfile(CONFIG_FILE):
        config.read(CONFIG_FILE)
        config.remove_option(section, name)
        with open(CONFIG_FILE, 'wb') as configfile:
            config.write(configfile)

if __name__ == '__main__':

    def test_is_well_formed_seed_string():
        well_formed = 'seed.openbazaar.org:8080,5b44be5c18ced1bc9400fe5e79c8ab90204f06bebacc04dd9c70a95eaca6e117'
        # test ill-formed url's (build fails with pylint error if we use long/descriptive names
        # key too short
#        bad_1 = 'seed.openbazaar.org:8080,5b44be5c18ced1bc9400fe5e79'
        # no port number
#        bad_2 = 'seed.openbazaar.org,5b44be5c18ced1bc9400fe5e79c8ab90204f06bebacc04dd9c70a95eaca6e117'
        # no host name in url
#        bad_3 = 'openbazaar.org:8080,5b44be5c18ced1bc9400fe5e79c8ab90204f06bebacc04dd9c70a95eaca6e117'

        assert _is_well_formed_seed_string(well_formed)
#        assert not _is_well_formed_seed_string(b1)
#        assert not _is_well_formed_seed_string(b2)
#        assert not _is_well_formed_seed_string(b3)

    def test_is_seed_tuple():
        good = ('seed.openbazaar.org:8080', '5b44be5c18ced1bc9400fe5e79c8ab90204f06bebacc04dd9c70a95eaca6e117')
        bad_not_tuple = 'seed.openbazaar.org:8080,5b44be5c18ced1bc9400fe5e79c8ab90204f06bebacc04dd9c70a95eaca6e117'
        bad_not_seed_tuple = ('aoioai', 'aoioai')
        assert _is_tuple(good, "seed")
        assert not _is_tuple(bad_not_tuple, "seed")
        assert not _is_tuple(bad_not_seed_tuple, "seed")


    _is_linux()
    _is_windows()
    _is_osx()
    if _is_linux():
        assert not _is_windows()
        assert not _is_osx()

    test_is_well_formed_seed_string()
    test_is_seed_tuple()
