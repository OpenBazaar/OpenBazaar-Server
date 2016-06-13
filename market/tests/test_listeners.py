from twisted.trial import unittest
from twisted.python import log
from mock import MagicMock
import mock

from market.listeners import MessageListenerImpl, BroadcastListenerImpl, NotificationListenerImpl
from protos.objects import PlaintextMessage

class MarketListenersTest(unittest.TestCase):

    def setUp(self):
        self.catcher = []
        observer = self.catcher.append
        log.addObserver(observer)
        self.addCleanup(log.removeObserver, observer)
        self.db = MagicMock()
        self.ws = MagicMock()

    @staticmethod
    def _create_valid_plaintext_message(handle):
        p = PlaintextMessage()
        p.sender_guid = 'test_guid'
        p.handle = handle
        p.pubkey = 'test_pubkey'
        p.subject = 'test_subject'
        p.type = 1
        p.message = 'test_message'
        p.timestamp = 10
        p.avatar_hash = 'test_avatar_hash'
        return p

    @staticmethod
    def _create_valid_message_json(handle):
        new_line = '\n'
        tab = '    '
        nlt = new_line + tab
        nldt = nlt + tab
        if handle != '':
            handle = '"handle": "'+handle+'", ' + nldt
        message = '{' + nlt + '"message": {' + nldt + \
            '"public_key": "746573745f7075626b6579", ' + nldt + handle + \
            '"sender": "746573745f67756964", ' + nldt + \
            '"timestamp": 10, ' + nldt + \
            '"avatar_hash": "746573745f6176617461725f68617368", ' + nldt + \
            '"message": "test_message", ' + nldt + \
            '"message_type": "ORDER", ' + nldt + \
            '"subject": "test_subject"' + nlt + '}\n}'
        return message

    def test_MarketListeners_notify_without_handle_success(self):
        '''MessageListenerImpl correctly notify without handle.'''
        p = self._create_valid_plaintext_message('')
        signature = 'test_signature'
        l = MessageListenerImpl(self.ws, self.db)
        l.notify(p, signature)
        self.db.messages.save_message.assert_called_with('746573745f67756964',
                                                         u'', 'test_pubkey',
                                                         u'test_subject',
                                                         'ORDER',
                                                         u'test_message', 10,
                                                         'test_avatar_hash',
                                                         signature, False)
        self.ws.push.assert_called_with(self._create_valid_message_json(''))

    def test_MarketListeners_notify_with_handle_success(self):
        '''MessageListenerImpl correctly notify with handle.'''
        p = self._create_valid_plaintext_message('test_handle')
        signature = 'test_signature'
        l = MessageListenerImpl(self.ws, self.db)
        l.notify(p, signature)
        self.db.messages.save_message.assert_called_with('746573745f67756964',
                                                         u'test_handle',
                                                         'test_pubkey',
                                                         u'test_subject',
                                                         'ORDER',
                                                         u'test_message', 10,
                                                         'test_avatar_hash',
                                                         signature, False)
        self.ws.push.assert_called_with(self._create_valid_message_json('test_handle'))

    def test_MarketListeners_save_message_exception(self):
        p = self._create_valid_plaintext_message('test_handle')
        signature = 'test_signature'
        l = MessageListenerImpl(self.ws, self.db)
        self.db.messages.save_message.side_effect = Exception("test_exception")
        l.notify(p, signature)
        self.assertEqual('[ERROR] Market.Listener.notify Exception: test_exception', self.catcher[0]['message'][0])

    def test_MarketListeners_broadcast_notify_success(self):
        '''BroadcastListenerImpl correctly notifies.'''
        b = BroadcastListenerImpl(self.ws, self.db)
        b.notify('123', 'test_message')
        self.db.broadcasts.save_broadcast.assert_called_once_with(mock.ANY,
                                                                  '313233', '',
                                                                  'test_message',
                                                                  mock.ANY, '')
        self.ws.push.assert_called_once_with(mock.ANY)

    def test_MarketListeners_notifiation_notify_success(self):
        n = NotificationListenerImpl(self.ws, self.db)
        n.notify('1231', 'test_handle', 'test_notify_type', 'test_order_id',
                 'test_title', 'test_image_hash')
        self.db.notifications.save_notification.assert_called_once_with(mock.ANY, '31323331', 'test_handle',
                                                                        'test_notify_type', 'test_order_id',
                                                                        'test_title', mock.ANY, 'test_image_hash')
        self.ws.push.assert_called_once_with(mock.ANY)

    def test_MarketListeners_notifiation_push_success(self):
        notification_json = {
            "notification": {
                "guid": "guid"
            }
        }
        n = NotificationListenerImpl(self.ws, self.db)
        n.push_ws(notification_json)
        self.ws.push.assert_called_once_with('{\n    "notification": {\n        "guid": "guid"\n    }\n}')
