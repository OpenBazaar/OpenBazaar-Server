__author__ = 'chris'
import sys
import argparse
import json

from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy

def doContinue(value):
    pass

def printValue(value):
    print json.dumps(value, indent=4)
    reactor.stop()

def printError(error):
    print 'error', error
    reactor.stop()

class Parser(object):

    def __init__(self, proxy):
        parser = argparse.ArgumentParser(
            description='OpenBazaar Network CLI',
            usage='''
    python network-cli.py command [<arguments>]

commands:
    getinfo          returns an object containing various state info
    get              fetches the given keyword from the dht
    set              sets the given keyword/key in the dht
    delete           deletes the keyword/key from the dht
    shutdown         closes all outstanding connections.
''')
        parser.add_argument('command', help='Execute the given command')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            parser.print_help()
            exit(1)
        getattr(self, args.command)()
        self.proxy = proxy

    def get(self):
        parser = argparse.ArgumentParser(
            description="Fetch the given keyword from the dht and return all the entries",
            usage='''usage:
    network-cli.py get [-kw KEYWORD]''')
        parser.add_argument('-kw', '--keyword', required=True, help="the keyword to fetch")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        d = proxy.callRemote('get', keyword)
        d.addCallbacks(printValue, printError)
        reactor.run()

    def set(self):
        parser = argparse.ArgumentParser(
            description='Set the given keyword/key pair in the dht. The value will be your serialized node information.',
            usage='''usage:
    network-cli.py set [-kw KEYWORD] [-k KEY]''')
        parser.add_argument('-kw', '--keyword', required=True, help="the keyword to set in the dht")
        parser.add_argument('-k', '--key', required=True, help="the key to set at the keyword")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        key = args.key
        d = proxy.callRemote('set', keyword, key)
        d.addCallbacks(printValue, printError)
        reactor.run()

    def delete(self):
        parser = argparse.ArgumentParser(
            description="Deletes the given keyword/key from the dht. Signature will be automatically generated.",
            usage='''usage:
    network-cli.py delete [-kw KEYWORD] [-k KEY]''')
        parser.add_argument('-kw', '--keyword', required=True, help="where to find the key")
        parser.add_argument('-k', '--key', required=True, help="the key to delete")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        key = args.key
        d = proxy.callRemote('delete', keyword, key)
        d.addCallbacks(printValue, printError)
        reactor.run()

    def getinfo(self):
        parser = argparse.ArgumentParser(
            description="Returns an object containing various state info",
            usage='''usage:
    network-cli getinfo''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getinfo')
        d.addCallbacks(printValue, printError)
        reactor.run()

    def shutdown(self):
        parser = argparse.ArgumentParser(
            description="Terminates all outstanding connections.",
            usage='''usage:
    network-cli shutdown''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('shutdown')
        d.addCallbacks(printValue, printError)
        reactor.run()

proxy = Proxy('127.0.0.1', 18465)
Parser(proxy)