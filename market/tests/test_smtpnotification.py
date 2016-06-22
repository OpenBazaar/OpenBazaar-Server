from twisted.trial import unittest
from twisted.python import log
from mock import patch, MagicMock
import mock
from smtplib import SMTPAuthenticationError

from market.smtpnotification import SMTPNotification

class MarketSMTPTest(unittest.TestCase):

    def setUp(self):
        self.catcher = []
        observer = self.catcher.append
        log.addObserver(observer)
        self.addCleanup(log.removeObserver, observer)
        self.db = MagicMock()
        self.db.settings.get.return_value = ['0', '1', '2', '3', '4', '5', '6',
                                             '7', '8', '9', '10', '11', '12',
                                             '13', 1, 'test_server',
                                             'test_sender', 'test_recipient',
                                             'test_username', 'test_password']

    def test_MarketSmtp_settings_success(self):
        '''SMTP Notification settings correctly set.'''
        s = SMTPNotification(self.db)
        self.assertEqual('test_server', s.server)
        self.assertEqual('test_sender', s.sender)
        self.assertEqual('test_recipient', s.recipient)
        self.assertEqual('test_username', s.username)
        self.assertEqual('test_password', s.password)

    @patch("smtplib.SMTP")
    def test_MarketSmtp_send_enabled_success(self, mock_smtp):
        '''Email sent when enabled'''
        instance = mock_smtp.return_value
        s = SMTPNotification(self.db)
        s.send('test_subject', 'test_body')
        mock_smtp.assert_called_once_with('test_server')
        instance.login.assert_called_once_with('test_username', 'test_password')
        instance.sendmail.assert_called_once_with('test_sender', 'test_recipient', mock.ANY)

    @patch("smtplib.SMTP")
    def test_MarketSmtp_send_disabled_not_sent(self, mock_smtp):
        '''Email not sent when disabled'''
        instance = mock_smtp.return_value
        self.db.settings.get.return_value = ['0', '1', '2', '3', '4', '5', '6',
                                             '7', '8', '9', '10', '11', '12',
                                             '13', 0, 'test_server',
                                             'test_sender', 'test_recipient',
                                             'test_username', 'test_password']
        s = SMTPNotification(self.db)
        s.send('test_subject', 'test_body')
        assert mock_smtp.call_count == 0
        assert instance.login.call_count == 0
        assert instance.sendmail.call_count == 0

    @patch("smtplib.SMTP")
    def test_MarketSmtp_send_throw_smtpexception(self, mock_smtp):
        '''Email sent when enabled'''
        catcher = self.catcher
        mock_smtp.side_effect = SMTPAuthenticationError(50, 'Test error thrown')
        s = SMTPNotification(self.db)
        s.send('test_subject', 'test_body')
        mock_smtp.assert_called_once_with('test_server')
        catch_exception = catcher.pop()
        self.assertEquals(catch_exception["message"][0], "[ERROR] Authentication Error: (50, 'Test error thrown')")

    @patch("smtplib.SMTP")
    def test_MarketSmtp_send_throw_exception(self, mock_smtp):
        '''Email sent when enabled'''
        catcher = self.catcher
        mock_smtp.side_effect = Exception('Test exception thrown')
        s = SMTPNotification(self.db)
        s.send('test_subject', 'test_body')
        mock_smtp.assert_called_once_with('test_server')
        catch_exception = catcher.pop()
        self.assertEquals(catch_exception["message"][0], "[ERROR] Test exception thrown")
