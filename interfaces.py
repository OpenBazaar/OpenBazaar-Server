__author__ = 'chris'

from zope.interface import Interface, Attribute


class Multiplexer(Interface):
    """
    This interface defines the structure of the protocol class that handles creating new network connections
    and sending and receiving messages. At present this is only used by the OpenBazaarProtocol class which
    is the protocol for our UDP server. In the future if we want to add additional transports, like I2P, we
    they will need to implement this interface so as to not break the rest of the code.
    """

    processors = Attribute("""A list of `MessageProcessors`""")
    testnet = Attribute("""`bool` are we using testnet""")
    vendors = Attribute("""A list `dht.node.Node` vendors""")
    ws = Attribute("""The websocket API server""")
    blockchain = Attribute("""The `LibbitcoinClient` instance""")

    def register_processor(processor):
        """
        A method add a `MessageProcessor` to the processors attribute.
        """

    def unregister_processor(processor):
        """
        Remove a `MessageProcessor` from the processors list.
        """

    def set_servers(ws, blockchain):
        """
        Set the ws and blockchain attributes.
        """

    def send_message(datagram, address, relay_addr):
        """
        Send a message over the wire to the given address

        Args:
            datagram: the serialized message to send
            address: the recipients address `tuple`
            relay_addr: a replay address `tuple` if used, otherwise None
        """

    def __getitem__(addr):
        """
        Return the `Connection` of the given address.

        Args:
            addr: Tuple of destination address (ip, port).
        Raises:
            KeyError: No connection is handling the given address.
        """


class ConnectionHandler(Interface):
    """
    A handler class for each connection.
    """
    connection = Attribute("""a `Connection` object for this handler""")
    node = Attribute("""a `dht.node.Node` object for the peer. This may be set after receiving the first message""")
    processors = Attribute("""A list of `MessageProcessors`""")

    def receive_message(datagram):
        """
        Receive a datagram over the wire.
        """

    def check_new_connection():
        """
        Return True if this is the first time this is called else False
        """


class Connection(Interface):
    """
    A class representing a connection to a remote peer
    """

    handler = Attribute("""a `ConnectionHandler` object for this connection""")
    state = Attribute("""a `txrudp.connection.State` enum showing this connection's state""")

    def send_message(message):
        """
        Send the serialized message to the remote peer.
        """


class MessageProcessor(Interface):
    """
    This is an interface for processing messages coming off the wire. Classes that implement this interface should be
    passed into 'OpenBazaarProtocol.register_processor' which will parse new messages to determine the message type
    then route them to the correct processor.
    """

    multiplexer = Attribute("""The main `ConnectionMultiplexer` protocol.
        We pass it in here so we can send datagrams from this class.""")

    def receive_message(datagram, sender, connection, ban_score):
        """
        Called by OpenBazaarProtocol when it receives a new message intended for this processor.

        Args:
            datagram: The protobuf that came off the wire in unserialized format. Basic validity checks, such as
                      minimum size and valid protobuf format have already been done.

            sender: a `node.Node` object sent by the sender.

            connection: the txrudp connection to the peer who sent the message. To respond directly to the peer call
                      connection.send_message()
            ban_score: a `net.dos.BanScore` object used to keep track of misbehaving peers. We need it here because
                the processor determines if the incoming message is a request or a response before passing it into
                the BanScore.
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