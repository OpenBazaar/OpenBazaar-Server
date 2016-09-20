__author__ = 'chris'

from log import Logger
from protos.message import Command, FOLLOW, UNFOLLOW
from twisted.internet import reactor, task

RECONNECTIONS = 100
MALFORMATED = 110

SCORES = {
    FOLLOW: 0,
    UNFOLLOW: 0
}


class BanScore(object):

    def __init__(self, multiplexer, ban_time=86400):
        self.multiplexer = multiplexer
        self.ban_time = ban_time
        self.peers = {}
        self.scoring_loop = task.LoopingCall(self.adjust_scores)
        self.scoring_loop.start(30, now=False)
        self.log = Logger(system=self)

    def process_message(self, peer, message):
        if peer[0] not in self.peers:
            self.peers[peer[0]] = SCORES.copy()

        try:
            if message.command == FOLLOW:
                self.peers[peer[0]][FOLLOW] += 1
                if self.peers[peer[0]][FOLLOW] > 3:
                    self.ban(peer, FOLLOW)
            elif message.command == UNFOLLOW:
                self.peers[peer[0]][UNFOLLOW] += 1
                if self.peers[peer[0]][UNFOLLOW] > 3:
                    self.ban(peer, UNFOLLOW)

        except Exception:
            self.log.warning("Exception processing banscore")

    def ban(self, peer, message_type):
        reason = Command.Name(message_type)
        self.log.warning("Banned %s. Reason: too many %s messages." %
                         (peer[0], reason))
        self.multiplexer.ban_ip(peer[0])
        if peer in self.multiplexer:
            self.multiplexer[peer].shutdown()
        reactor.callLater(self.ban_time, self.multiplexer.remove_ip_ban, peer[0])

    def adjust_scores(self):
        for peer in self.peers.keys():
            remove = True
            for k, v in self.peers[peer].items():
                if v > 0:
                    remove = False
                    self.peers[peer][k] = v - 1
            if remove:
                del self.peers[peer]
