__author__ = 'chris'
import sys
import argparse
import json

from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy


def do_continue(value):
    pass


def print_value(value):
    print json.dumps(value, indent=4)
    reactor.stop()


def print_error(error):
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
    getpeers         returns the id of all the peers in the routing table
    get              fetches the given keyword from the dht
    set              sets the given keyword/key in the dht
    delete           deletes the keyword/key from the dht
    getnode          returns a node's ip address given its guid.
    getcontract      fetchs a contract from a node given its hash and guid
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
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def set(self):
        parser = argparse.ArgumentParser(
            description='Set the given keyword/key pair in the dht. The value will be your '
                        'serialized node information.',
            usage='''usage:
    network-cli.py set [-kw KEYWORD] [-k KEY]''')
        parser.add_argument('-kw', '--keyword', required=True, help="the keyword to set in the dht")
        parser.add_argument('-k', '--key', required=True, help="the key to set at the keyword")
        args = parser.parse_args(sys.argv[2:])
        keyword = args.keyword
        key = args.key
        d = proxy.callRemote('set', keyword, key)
        d.addCallbacks(print_value, print_error)
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
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getinfo(self):
        parser = argparse.ArgumentParser(
            description="Returns an object containing various state info",
            usage='''usage:
    network-cli getinfo''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getinfo')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def shutdown(self):
        parser = argparse.ArgumentParser(
            description="Terminates all outstanding connections.",
            usage='''usage:
    network-cli shutdown''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('shutdown')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getpubkey(self):
        parser = argparse.ArgumentParser(
            description="Returns this node's public key.",
            usage='''usage:
    network-cli getpubkey''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getpubkey')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getcontract(self):
        parser = argparse.ArgumentParser(
            description="Fetch a contract given its hash and guid.",
            usage='''usage:
    network-cli.py getcontract [-c HASH] [-g GUID]''')
        parser.add_argument('-c', '--hash', required=True, help="the keyword to fetch")
        parser.add_argument('-g', '--guid', required=True, help="the keyword to fetch")
        args = parser.parse_args(sys.argv[2:])
        hash = args.hash
        guid = args.guid
        d = proxy.callRemote('getcontract', hash, guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getpeers(self):
        parser = argparse.ArgumentParser(
            description="Returns id of all peers in the routing table",
            usage='''usage:
    network-cli getpeers''')
        args = parser.parse_args(sys.argv[2:])
        d = proxy.callRemote('getpeers')
        d.addCallbacks(print_value, print_error)
        reactor.run()

    def getnode(self):
        parser = argparse.ArgumentParser(
            description="Fetch the ip address for a node given its guid.",
            usage='''usage:
    network-cli.py getnode [-g GUID]''')
        parser.add_argument('-g', '--guid', required=True, help="the keyword to fetch")
        args = parser.parse_args(sys.argv[2:])
        guid = args.guid
        d = proxy.callRemote('getnode', guid)
        d.addCallbacks(print_value, print_error)
        reactor.run()

proxy = Proxy('127.0.0.1', 18465)
Parser(proxy)