__author__ = 'chris'
from twisted.internet import reactor, task
from protos.message import PING, Command
from log import Logger


class BanScore(object):

    def __init__(self, peer_ip, multiplexer, ban_time=86400):
        self.peer_ip = peer_ip
        self.multiplexer = multiplexer
        self.ban_time = ban_time
        self.scores = {
            PING: 0
            # place holder for other messages
        }
        task.LoopingCall(self.adjust_scores).start(30)
        self.log = Logger(system=self)

    def process_message(self, message):
        if message.command == PING:
            self.scores[PING] += 1
            if self.scores[PING] > 4:
                self.ban(PING)

    def ban(self, message_type):
        self.log.warning("Banned %s. Reason: to many %s messages" %
                         (self.peer_ip, Command.Name(message_type)))
        self.multiplexer.ban_ip(self.peer_ip)
        self.multiplexer[self.peer_ip].shutdown()
        reactor.callLater(self.ban_time, self.multiplexer.remove_ip_ban, self.peer_ip)

    def adjust_scores(self):
        for k, v in self.scores.items():
            if v > 0:
                self.scores[k] = v - 1
