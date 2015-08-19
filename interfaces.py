__author__ = 'chris'

from zope.interface import Interface, Attribute

class MessageProcessor(Interface):
    """
    This is an interface for processing messages coming off the wire. Classes that implement this interface should be
    passed into 'OpenBazaarProtocol.register_processor' which will parse new messages to determine the message type
    then route them to the correct processor.
    """

    multiplexer = Attribute("""The main `ConnectionMultiplexer` protocol.
        We pass it in here so we can send datagrams from this class.""")

    def receive_message(datagram, connection):
        """
        Called by OpenBazaarProtocol when it receives a new message intended for this processor.

        Args:
            datagram: The protobuf that came off the wire in unserialized format. Basic validity checks, such as
                      minimum size and valid protobuf format have already been done.

            connection: the txrudp connection to the peer who sent the message. To respond directly to the peer call
                      connection.send_message()
        """

    def connect_multiplexer(multiplexer):
        """
        Connect the main ConnectionMultiplexer to this class so we can send outgoing messages.
        """

    def __iter__():
        """
        OpenBazaarProtocol will use this to check which message types are handled by this processor.
        :return: iter([list of enums])
        """

class NotificationListener(Interface):
    """
    An interface for handling notifications sent to followers.
    """

    def notify(guid, message):
        """
        New notifications will be sent here. They will only show if this node is following the node
        which sent the notification.
        """

class MessageListener(Interface):
    """
    An interface for handling messages sent between nodes.
    """

    def notify(plaintext_message, signature):
        """
        New messages will be sent here if they decrypt and parse correctly.
        Args:
            plaintext_message: the protobuf object containing the message
            signature: the signature covering the message.
        """