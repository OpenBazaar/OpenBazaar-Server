__author__ = 'chris'

from zope.interface import Interface

class MessageProcessor(Interface):
    """
    This is an interface for processing messages coming off the wire. Classes that implement this interface should be
    passed into 'OpenBazaarProtocol.register_processor' which will parse new messages to determine the message type
    then route them to the correct processor.
    """

    def receive_message(self, datagram, connection):
        """
        Called by OpenBazaarProtocol when it receives a new message intended for this processor.

        Args:
            datagram: The protobuf that came off the wire in unserialized format. Basic validity checks, such as
                      minimum size and valid protobuf format have already been done.

            connection: the txrudp connection to the peer who sent the message. To respond directly to the peer call
                      connection.send_message()
        """

    def __iter__(self):
        """
        OpenBazaarProtocol will use this to check which message types are handled by this processor.
        :return: iter([list of enums])
        """
