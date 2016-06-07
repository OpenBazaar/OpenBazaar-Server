__author__ = 'chris'

from log import Logger
from protos.message import Command, PING, STUN, STORE, INV, VALUES, GET_LISTINGS, FOLLOW, UNFOLLOW
from twisted.internet import reactor, task

RECONNECTIONS = 100
MALFORMATED = 110

SCORES = {
    PING: 0,
    STUN: 0,
    STORE: 0,
    INV: 0,
    VALUES: 0,
    GET_LISTINGS: 0,
    FOLLOW: 0,
    UNFOLLOW: 0,
    RECONNECTIONS: 0,
    MALFORMATED: 0
}


class BanScore(object):

    def __init__(self, multiplexer, ban_time=86400):
        self.multiplexer = multiplexer
        self.ban_time = ban_time
        self.peers = {}
        self.scoring_loop = task.LoopingCall(self.adjust_scores)
        #self.scoring_loop.start(30, now=False)
        self.log = Logger(system=self)

    def process_message(self, peer, message):
        if peer:
            # disabled for now
            return
        if peer[0] not in self.peers:
            self.peers[peer[0]] = SCORES.copy()

        try:
            if message == 100:
                self.peers[peer[0]][RECONNECTIONS] += 1
                if self.peers[peer[0]][RECONNECTIONS] > 10:
                    self.ban(peer, RECONNECTIONS)
                return
            elif message == 110:
                self.peers[peer[0]][MALFORMATED] += 1
                if self.peers[peer[0]][MALFORMATED] > 10:
                    self.ban(peer, MALFORMATED)
                return
            if message.command == PING:
                self.peers[peer[0]][PING] += 0.5
                if self.peers[peer[0]][PING] > 10:
                    self.ban(peer, PING)
            elif message.command == STUN:
                self.peers[peer[0]][STUN] += 1
                if self.peers[peer[0]][STUN] > 1:
                    self.ban(peer, STUN)
            elif message.command == STORE:
                args = tuple(message.arguments)
                for arg in args:
                    self.peers[peer[0]][STORE] += len(arg)
                if self.peers[peer[0]][STORE] > 1000000:
                    self.ban(peer, STORE)
            elif message.command == INV:
                self.peers[peer[0]][INV] += 30
                if self.peers[peer[0]][INV] > 150:
                    self.ban(peer, INV)
            elif message.command == VALUES:
                self.peers[peer[0]][VALUES] += 30
                if self.peers[peer[0]][VALUES] > 150:
                    self.ban(peer, VALUES)
            elif message.command == GET_LISTINGS:
                self.peers[peer[0]][GET_LISTINGS] += 5
                if self.peers[peer[0]][GET_LISTINGS] > 250:
                    self.ban(peer, GET_LISTINGS)
            elif message.command == FOLLOW:
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
        if message_type == 100:
            reason = "RECONNECTIONS"
        elif message_type == 110:
            reason = "MALFORMATTED"
        else:
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
                    if k == STORE:
                        self.peers[peer][k] = v - 350
                    else:
                        self.peers[peer][k] = v - 1
            if remove:
                del self.peers[peer]
