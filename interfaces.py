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

    def receive_message(datagram, connection, ban_score):
        """
        Called by OpenBazaarProtocol when it receives a new message intended for this processor.

        Args:
            datagram: The protobuf that came off the wire in unserialized format. Basic validity checks, such as
                      minimum size and valid protobuf format have already been done.

            connection: the txrudp connection to the peer who sent the message. To respond directly to the peer call
                      connection.send_message()

            ban_score: a `net.dos.BanScore` object for tracking a peer's behavior.
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


class BroadcastListener(Interface):
    """
    An interface for handling broadcasts sent to followers.
    """

    def notify(guid, message):
        """
        New broadcasts will be sent here. They will only show if this node is following the node
        which sent the broadcast.
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


class NotificationListener(Interface):
    """
    An interface for handling event notifications. New events should update this
    listener which will save the notifications to the db and push it to UI via websockets.
    """

    def notify(guid, handle, type, order_id, title, image_hash):
        """
        This should be called to register a new notification.
        Args:
            guid: (in hex) optional depending on notification type.
            handle: optional depending on notification type.
            type: a `String` containing the type of notification,
                  (ex: Follow, New Order, Order Confirmation, Payment Received).
            order_id: an order id if this notification is for an order
            title: a `String` which can be used for the item's title if an order notification.
            image_hash: optional depending on notification type.
        """