__author__ = 'chris'
import sys
import argparse
import platform
from twisted.internet import reactor
from twisted.python import log, logfile
from twisted.web.server import Site
from twisted.web.static import File
from daemon import Daemon

import stun
import requests
from autobahn.twisted.websocket import listenWS

from libbitcoin import LibbitcoinClient
from db.datastore import Database
from keyutils.keys import KeyChain
from dht.network import Server
from dht.node import Node
from wireprotocol import OpenBazaarProtocol
from constants import DATA_FOLDER, KSIZE, ALPHA
from market import network
from market.listeners import MessageListenerImpl, NotificationListenerImpl
from api.ws import WSFactory, WSProtocol
from api.restapi import OpenBazaarAPI
from dht.storage import PersistentStorage, ForgetfulStorage
from market.profile import Profile
from log import Logger, FileLogObserver

def run(*args):
    TESTNET = args[0]

    # database
    db = Database(TESTNET)

    # key generation
    keys = KeyChain(db)

    # logging
    # TODO: prune this log file and prevent it from getting too large?
    logFile = logfile.LogFile.fromFullPath(DATA_FOLDER + "debug.log")
    log.addObserver(FileLogObserver(logFile, level=args[1]).emit)
    log.addObserver(FileLogObserver(level=args[1]).emit)
    logger = Logger(system="OpenBazaard")

    # stun
    port = args[2]
    logger.info("Finding NAT Type..")
    # TODO: maintain a list of backup STUN servers and try them if ours fails
    try:
        response = stun.get_ip_info(source_port=port)
    except Exception:
        response = stun.get_ip_info()
    logger.info("%s on %s:%s" % (response[0], response[1], response[2]))
    ip_address = response[1]
    port = response[2]

    # TODO: try UPnP if restricted NAT

    # TODO: maintain open connection to seed node if STUN/UPnP fail

    # TODO: use TURN if symmetric NAT

    def on_bootstrap_complete(resp):
        logger.info("bootstrap complete, downloading outstanding messages...")
        mlistener = MessageListenerImpl(ws_factory, db)
        mserver.get_messages(mlistener)
        mserver.protocol.add_listener(mlistener)
        nlistener = NotificationListenerImpl(ws_factory, db)
        mserver.protocol.add_listener(nlistener)

        # TODO: after bootstrap run through any pending contracts and see if the bitcoin address
        # has been funded, if not listen on the address and start the 10 minute delete timer.

    protocol = OpenBazaarProtocol((ip_address, port), testnet=TESTNET)

    # kademlia
    node = Node(keys.guid, ip_address, port, signed_pubkey=keys.guid_signed_pubkey, vendor=Profile(db).get().vendor)

    if node.vendor:
        storage = PersistentStorage(db.DATABASE)
    else:
        storage = ForgetfulStorage()

    try:
        kserver = Server.loadState(DATA_FOLDER + 'cache.pickle', ip_address, port, protocol, db,
                                   on_bootstrap_complete, storage=storage)
    except Exception:
        kserver = Server(node, db, KSIZE, ALPHA, storage=storage)
        kserver.protocol.connect_multiplexer(protocol)
        kserver.bootstrap(
            kserver.querySeed("seed.openbazaar.org:8080",
                              "5b44be5c18ced1bc9400fe5e79c8ab90204f06bebacc04dd9c70a95eaca6e117"))\
            .addCallback(on_bootstrap_complete)
        # TODO: load seeds from config file
    kserver.saveStateRegularly(DATA_FOLDER + 'cache.pickle', 10)
    protocol.register_processor(kserver.protocol)

    # market
    mserver = network.Server(kserver, keys.signing_key, db)
    mserver.protocol.connect_multiplexer(protocol)
    protocol.register_processor(mserver.protocol)

    reactor.listenUDP(port, protocol)

    # websockets api
    ws_factory = WSFactory("ws://127.0.0.1:18466", mserver, kserver)
    ws_factory.protocol = WSProtocol
    ws_factory.setProtocolOptions(allowHixie76=True)
    listenWS(ws_factory)
    webdir = File(".")
    web = Site(webdir)
    reactor.listenTCP(9000, web, interface="127.0.0.1")

    # rest api
    api = OpenBazaarAPI(mserver, kserver, protocol)
    site = Site(api, timeout=None)
    reactor.listenTCP(18469, site, interface="127.0.0.1")

    # TODO: add optional SSL on rest and websocket servers

    # blockchain
    # TODO: listen on the libbitcoin heartbeat port instead fetching height
    def height_fetched(ec, height):
        # TODO: re-broadcast any unconfirmed txs in the db using height to find confirmation status
        logger.info("Libbitcoin server online")
        try:
            timeout.cancel()
        except Exception:
            pass

    def timeout(client):
        print logger.critical("Libbitcoin server offline")
        client = None

    if TESTNET:
        libbitcoin_client = LibbitcoinClient("tcp://libbitcoin2.openbazaar.org:9091")
    else:
        libbitcoin_client = LibbitcoinClient("tcp://libbitcoin1.openbazaar.org:9091")

    # TODO: load libbitcoin server url from config file

    libbitcoin_client.fetch_last_height(height_fetched)
    timeout = reactor.callLater(5, timeout, libbitcoin_client)

    protocol.set_servers(ws_factory, libbitcoin_client)

    reactor.run()

if __name__ == "__main__":
    # pylint: disable=anomalous-backslash-in-string
    class OpenBazaard(Daemon):
        def run(self, *args):
            run(*args)

    class Parser(object):
        def __init__(self, daemon):
            self.daemon = daemon
            parser = argparse.ArgumentParser(
                description='OpenBazaard v0.1',
                usage='''
    python openbazaard.py <command> [<args>]
    python openbazaard.py <command> --help

commands:
    start            start the OpenBazaar server
    stop             shutdown the server and disconnect
    restart          restart the server
''')
            parser.add_argument('command', help='Execute the given command')
            args = parser.parse_args(sys.argv[1:2])
            if not hasattr(self, args.command):
                parser.print_help()
                exit(1)
            getattr(self, args.command)()

        def start(self):
            parser = argparse.ArgumentParser(
                description="Start the OpenBazaar server",
                usage='''usage:
        python openbazaard.py start [-d DAEMON]''')
            parser.add_argument('-d', '--daemon', action='store_true', help="run the server in the background")
            parser.add_argument('-t', '--testnet', action='store_true', help="use the test network")
            parser.add_argument('-l', '--loglevel', default="info",
                                help="set the loggin level [debug, info, warning, error, criticial]")
            parser.add_argument('-p', '--port', help="set the network port")
            args = parser.parse_args(sys.argv[2:])
            OKBLUE = '\033[94m'
            ENDC = '\033[0m'
            print "________             " + OKBLUE + "         __________" + ENDC
            print "\_____  \ ______   ____   ____" + OKBLUE + \
                  "\______   \_____  _____________  _____ _______" + ENDC
            print " /   |   \\\____ \_/ __ \ /    \\" + OKBLUE +\
                  "|    |  _/\__  \ \___   /\__  \ \__  \\\_  __ \ " + ENDC
            print "/    |    \  |_> >  ___/|   |  \    " + OKBLUE \
                  + "|   \ / __ \_/    /  / __ \_/ __ \|  | \/" + ENDC
            print "\_______  /   __/ \___  >___|  /" + OKBLUE + "______  /(____  /_____ \(____  (____  /__|" + ENDC
            print "        \/|__|        \/     \/  " + OKBLUE + "     \/      \/      \/     \/     \/" + ENDC
            print
            print "OpenBazaar Server v0.1 starting..."
            unix = ("linux", "linux2", "darwin")
            # TODO: run as windows service (also for STOP and RESTART)
            if args.port:
                port = int(args.port)
            else:
                port = 18467 if not args.testnet else 28467
            if args.daemon and platform.system().lower() in unix:
                self.daemon.start(args.testnet, args.loglevel, port)
            else:
                run(args.testnet, args.loglevel, port)

        def stop(self):
            # pylint: disable=W0612
            parser = argparse.ArgumentParser(
                description="Shutdown the server and disconnect",
                usage='''usage:
        python openbazaard.py stop''')
            print "OpenBazaar server stopping..."
            try:
                requests.get("http://localhost:18469/api/v1/shutdown")
            except Exception:
                self.daemon.stop()

        def restart(self):
            # pylint: disable=W0612
            parser = argparse.ArgumentParser(
                description="Restart the server",
                usage='''usage:
        python openbazaard.py restart''')
            print "Restarting OpenBazaar server..."
            self.daemon.restart()

    Parser(OpenBazaard('/tmp/openbazaard.pid'))
