"""
Copyright (c) 2014 Brian Muller
"""

import sys
from twisted.python import log

DEBUG = 5
WARNING = 4
INFO = 3
ERROR = 2
CRITICAL = 1

levels = {"debug": 5, "warning": 4, "info": 3, "error": 2, "critical": 1}

class FileLogObserver(log.FileLogObserver):
    def __init__(self, f=None, level="info", default=DEBUG):
        log.FileLogObserver.__init__(self, f or sys.stdout)
        self.level = levels[level]
        self.default = default

    def emit(self, eventDict):
        ll = eventDict.get('loglevel', self.default)
        if eventDict['isError'] or 'failure' in eventDict or self.level >= ll:
            log.FileLogObserver.emit(self, eventDict)


class Logger(object):
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def msg(self, message, **kw):
        kw.update(self.kwargs)
        if 'system' in kw and not isinstance(kw['system'], str):
            kw['system'] = kw['system'].__class__.__name__
        log.msg(message, **kw)

    def info(self, message, **kw):
        kw['loglevel'] = INFO
        self.msg("[INFO] %s" % message, **kw)

    def debug(self, message, **kw):
        kw['loglevel'] = DEBUG
        self.msg("[DEBUG] %s" % message, **kw)

    def warning(self, message, **kw):
        kw['loglevel'] = WARNING
        self.msg("[WARNING] %s" % message, **kw)

    def error(self, message, **kw):
        kw['loglevel'] = ERROR
        self.msg("[ERROR] %s" % message, **kw)

    def critical(self, message, **kw):
        kw['loglevel'] = CRITICAL
        self.msg("[CRITICAL] %s" % message, **kw)


try:
    theLogger
except NameError:
    theLogger = Logger()
    msg = theLogger.msg
    info = theLogger.info
    debug = theLogger.debug
    warning = theLogger.warning
    error = theLogger.error
    critical = theLogger.critical
