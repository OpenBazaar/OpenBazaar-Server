__author__ = 'chris'
from twisted.internet import reactor, task
from protos.message import Command, PING, STUN, STORE, HOLE_PUNCH, INV, VALUES
from log import Logger
from constants import SEED_NODE, SEED_NODE_TESTNET


class BanScore(object):

    def __init__(self, peer_ip, multiplexer, ban_time=86400):
        self.peer_ip = peer_ip
        self.multiplexer = multiplexer
        self.ban_time = ban_time
        self.scores = {
            PING: 0,
            STUN: 0,
            STORE: 0,
            INV: 0,
        }
        task.LoopingCall(self.adjust_scores).start(30)
        self.log = Logger(system=self)

    def process_message(self, message):
        if message.command == PING:
            self.scores[PING] += 1
            if self.scores[PING] > 4:
                self.ban(PING)
        elif message.command == STUN:
            self.scores[STUN] += 1
            if self.scores[STUN] > 0:
                self.ban(STUN)
        elif message.command == HOLE_PUNCH:
            if self.peer_ip[0] != SEED_NODE[0] or self.peer_ip[0] != SEED_NODE_TESTNET[0]:
                self.ban(HOLE_PUNCH)
        elif message.command == STORE:
            args = tuple(message.arguments)
            for arg in args:
                self.scores[STORE] += len(arg)
            if self.scores[STORE] > 1000000:
                self.ban(STORE)
        elif message.command == INV:
            self.scores[INV] += 30
            if self.scores[INV] > 120:
                self.ban(INV)
        elif message.command == VALUES:
            self.scores[VALUES] += 30
            if self.scores[VALUES] > 120:
                self.ban(VALUES)

    def ban(self, message_type):
        self.log.warning("Banned %s. Reason: too many %s messages." %
                         (self.peer_ip[0], Command.Name(message_type)))
        self.multiplexer.ban_ip(self.peer_ip[0])
        self.multiplexer[self.peer_ip].shutdown()
        reactor.callLater(self.ban_time, self.multiplexer.remove_ip_ban, self.peer_ip[0])

    def adjust_scores(self):
        for k, v in self.scores.items():
            if v > 0:
                if k == STORE:
                    self.scores[k] = v - 350
                else:
                    self.scores[k] = v - 1
