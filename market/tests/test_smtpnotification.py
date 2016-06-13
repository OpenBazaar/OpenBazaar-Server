from twisted.trial import unittest
from twisted.python import log
from mock import MagicMock

from market.smtpnotification import SMTPNotification

class MarketSMTPTest(unittest.TestCase):

    def setUp(self):
        self.catcher = []
        observer = self.catcher.append
        log.addObserver(observer)
        self.addCleanup(log.removeObserver, observer)
        self.db = MagicMock()

    def test_MarketSmtp_settings_success(self):
        '''SMTP Notification settings correctly set.'''
        self.db.settings.get.return_value = ['0', '1', '2', '3', '4', '5', '6',
                                             '7', '8', '9', '10', '11', '12',
                                             '13', '14', 'test_server',
                                             'test_sender', 'test_recipient',
                                             'test_username', 'test_password']
        s = SMTPNotification(self.db)
        self.assertEqual('test_server', s.server)
        self.assertEqual('test_sender', s.sender)
        self.assertEqual('test_recipient', s.recipient)
        self.assertEqual('test_username', s.username)
        self.assertEqual('test_password', s.password)
