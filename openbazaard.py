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

import dht.constants
import obelisk
from db.datastore import Database
from keyutils.keys import KeyChain
from dht.network import Server
from dht.node import Node
from wireprotocol import OpenBazaarProtocol
from constants import DATA_FOLDER
from market import network
from market.listeners import MessageListenerImpl, NotificationListenerImpl
from api.ws import WSFactory, WSProtocol
from api.restapi import OpenBazaarAPI
from dht.storage import PersistentStorage

def run(*args):
    TESTNET = args[0]

    # logging
    logFile = logfile.LogFile.fromFullPath(DATA_FOLDER + "debug.log")
    log.addObserver(log.FileLogObserver(logFile).emit)
    log.startLogging(sys.stdout)

    # stun
    port = 18467 if not TESTNET else 28467
    print "Finding NAT Type.."
    response = stun.get_ip_info(stun_host="stun.l.google.com", source_port=port, stun_port=19302)
    print "%s on %s:%s" % (response[0], response[1], response[2])
    ip_address = response[1]
    port = response[2]

    # database
    db = Database(TESTNET)

    # key generation
    keys = KeyChain(db)

    def on_bootstrap_complete(resp):
        mlistener = MessageListenerImpl(ws_factory, db)
        mserver.get_messages(mlistener)
        mserver.protocol.add_listener(mlistener)
        nlistener = NotificationListenerImpl(ws_factory, db)
        mserver.protocol.add_listener(nlistener)

    protocol = OpenBazaarProtocol((ip_address, port), testnet=TESTNET)

    # kademlia
    node = Node(keys.guid, ip_address, port, signed_pubkey=keys.guid_signed_pubkey)

    try:
        kserver = Server.loadState(DATA_FOLDER + 'cache.pickle', ip_address, port, protocol, db,
                                   on_bootstrap_complete, storage=PersistentStorage(db.DATABASE))
    except Exception:
        kserver = Server(node, db, dht.constants.KSIZE, dht.constants.ALPHA, storage=PersistentStorage(db.DATABASE))
        kserver.protocol.connect_multiplexer(protocol)
        kserver.bootstrap(
            kserver.querySeed("seed.openbazaar.org:8080",
                              "4b953c89a9e698e0cbff18811f849a4625c5895f6cc6b9c06d95d43f1c00959b"))\
            .addCallback(on_bootstrap_complete)

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

    # blockchain
    if TESTNET:
        libbitcoin_client = obelisk.ObeliskOfLightClient("tcp://testnet-baltic.airbitz.co:9091")
    else:
        libbitcoin_client = obelisk.ObeliskOfLightClient("tcp://libbitcoin1.openbazaar.org:9091")

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
            if args.daemon and platform.system().lower() in unix:
                self.daemon.start(args.testnet)
            else:
                run(args.testnet)

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
                pass
            self.daemon.stop()

        def restart(self):
            # pylint: disable=W0612
            parser = argparse.ArgumentParser(
                description="Restart the server",
                usage='''usage:
        python openbazaard.py restart''')
            print "Restarting OpenBazaar server..."
            self.daemon.restart()

    Parser(OpenBazaard('/tmp/daemon-example.pid'))
