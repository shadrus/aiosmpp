import asyncio
import logging

import binascii
import struct

from . import smpp
from . import consts
from .import exceptions


logger = logging.getLogger("SMPP.client")


class Client:
    def __init__(self):
        self.client = None

    def connect(self, host, port):
        client_reader, client_writer = asyncio.get_event_loop().run_until_complete(asyncio.open_connection(host,
                                                                          port))
        logger.info("Connected to %s %d", host, port)
        self.client = SMPPClientProtocol(client_reader, client_writer)

    def listen(self):
        asyncio.get_event_loop().run_until_complete(self.client.listen())

    def bind_transmitter(self, system_id, password):
        """Bind as a transmitter"""
        return self.client.bind_transmitter(system_id=system_id, password=password)

    def bind_receiver(self, system_id, password):
        """Bind as a receiver"""
        return self.client.bind_receiver(system_id=system_id, password=password)

    def bind_transceiver(self, system_id, password):
        """Bind as a transmitter and receiver at once"""
        return self.client.bind_transceiver(system_id=system_id, password=password)

    def disconnect(self):
        self.client.disconnect()

    def send_message(self, **kwargs):
        """Send message
        Required Arguments:
            source_addr_ton -- Source address TON
            source_addr -- Source address (string)
            dest_addr_ton -- Destination address TON
            destination_addr -- Destination address (string)
            short_message -- Message text (string)
        """
        return self.client.send_message(**kwargs)


class SMPPClientProtocol:
    """SMPP client class"""

    def __init__(self, reader, writer):
        """Initialize"""
        self.state = consts.SMPP_CLIENT_STATE_OPEN
        self.sequence_generator = SimpleSequenceGenerator()
        self.data = bytearray()
        self.reader = reader
        self.writer = writer

    def __del__(self):
        """Disconnect when client object is destroyed"""
        self.disconnect()

    async def listen(self, ignore_error_codes=None):
        """Listen for PDUs and act"""
        while True:
            try:
                p = await self.read_pdu()
                if p.is_error():
                    raise exceptions.PDUError(
                        '({}) {}: {}'.format(p.status, p.command,
                                             consts.DESCRIPTIONS.get(p.status, 'Unknown status')), int(p.status))

                if p.command == 'unbind':  # unbind_res
                    logger.info('Unbind command received')
                    self.state = consts.SMPP_CLIENT_STATE_CLOSED
                    break
                elif p.command == 'submit_sm_resp':
                    self.message_sent_handler(pdu=p)
                elif p.command == 'deliver_sm':
                    self._message_received(p)
                elif p.command == 'enquire_link':
                    self._enquire_link_received(pdu=p)
                elif p.command == 'enquire_link_resp':
                    pass
                else:
                    logger.warning('Unhandled SMPP command "%s"', p.command)
            except exceptions.PDUError as e:
                if ignore_error_codes \
                        and len(e.args) > 1 \
                        and e.args[1] in ignore_error_codes:
                    logging.warning('(%d) %s. Ignored.' %
                                    (e.args[1], e.args[0]))
                else:
                    raise

    @property
    def sequence(self):
        return self.sequence_generator.sequence

    def next_sequence(self):
        return self.sequence_generator.next_sequence()

    def disconnect(self):
        """Disconnect from the SMSC"""
        logger.info('Disconnecting...')
        if self.state != consts.SMPP_CLIENT_STATE_CLOSED:
            self.unbind()
        asyncio.get_event_loop().stop()

    def _bind(self, command_name, **kwargs):
        """Send bind_transmitter command to the SMSC"""

        if command_name in ('bind_receiver', 'bind_transceiver'):
            logger.debug('Receiver mode')
            self.receiver_mode = True

        p = smpp.make_pdu(command_name, client=self, **kwargs)
        self.send_pdu(p)
        asyncio.get_event_loop().run_until_complete(self.read_pdu())
        self.state = consts.SMPP_CLIENT_STATE_BOUND_TX

    def bind_transmitter(self, **kwargs):
        """Bind as a transmitter"""
        return self._bind('bind_transmitter', **kwargs)

    def bind_receiver(self, **kwargs):
        """Bind as a receiver"""
        return self._bind('bind_receiver', **kwargs)

    def bind_transceiver(self, **kwargs):
        """Bind as a transmitter and receiver at once"""
        return self._bind('bind_transceiver', **kwargs)

    def unbind(self):
        """Unbind from the SMSC"""

        p = smpp.make_pdu('unbind', client=self)
        self.send_pdu(p)

    def send_pdu(self, p):
        """Send PDU to the SMSC"""
        if not self.state in consts.COMMAND_STATES[p.command]:
            raise exceptions.PDUError("Command %s failed: %s" %
                                      (p.command, consts.DESCRIPTIONS[consts.SMPP_ESME_RINVBNDSTS]))

        logger.debug('Sending %s PDU', p.command)
        generated = p.generate()
        logger.debug('>>%s (%d bytes)', binascii.b2a_hex(generated),
                     len(generated))
        self.writer.write(generated)
        return True

    async def read_pdu(self):
        """Read PDU from the SMSC"""

        logger.debug('Waiting for PDU...')

        raw_len = await self.reader.read(4)
        try:
            length = struct.unpack('>L', raw_len)[0]
        except struct.error:
            logger.warning('Receive broken pdu... %s', repr(raw_len))
            raise exceptions.PDUError('Broken PDU')

        raw_pdu = await self.reader.read(length - 4)
        raw_pdu = raw_len + raw_pdu

        logger.debug('<<%s (%d bytes)', binascii.b2a_hex(raw_pdu), len(raw_pdu))

        p = smpp.parse_pdu(raw_pdu, client=self)

        logger.debug('Read %s PDU', p.command)

        if p.is_error():
            return p

        elif p.command in consts.STATE_SETTERS:
            self.state = consts.STATE_SETTERS[p.command]

        return p

    def accept(self, obj):
        """Accept an object"""
        raise NotImplementedError('not implemented')

    def _message_received(self, p):
        """Handler for received message event"""
        self.message_received_handler(pdu=p)
        dsmr = smpp.make_pdu('deliver_sm_resp', client=self)
        dsmr.sequence = p.sequence
        self.send_pdu(dsmr)

    def _enquire_link_received(self, pdu):
        """Response to enquire_link"""
        ler = smpp.make_pdu('enquire_link_resp', sequence=pdu.sequence, client=self)
        self.send_pdu(ler)
        logger.debug("Link Enquiry...")

    def set_message_received_handler(self, func):
        """Set new function to handle message receive event"""
        self.message_received_handler = func

    def set_message_sent_handler(self, func):
        """Set new function to handle message sent event"""
        self.message_sent_handler = func

    @staticmethod
    def message_received_handler(pdu, **kwargs):
        """Custom handler to process received message. May be overridden"""
        logger.warning('Message received handler (Override me)')

    @staticmethod
    def message_sent_handler(pdu, **kwargs):
        """Called when SMPP server accept message (SUBMIT_SM_RESP).
        May be overridden"""
        logger.warning('Message sent handler (Override me)')

    def send_message(self, **kwargs):
        """Send message
        Required Arguments:
            source_addr_ton -- Source address TON
            source_addr -- Source address (string)
            dest_addr_ton -- Destination address TON
            destination_addr -- Destination address (string)
            short_message -- Message text (string)
        """
        ssm = smpp.make_pdu('submit_sm', client=self, **kwargs)
        self.send_pdu(ssm)
        return ssm


class SimpleSequenceGenerator(object):

    MIN_SEQUENCE = 0x00000001
    MAX_SEQUENCE = 0x7FFFFFFF

    def __init__(self):
        self._sequence = self.MIN_SEQUENCE

    @property
    def sequence(self):
        return self._sequence

    def next_sequence(self):
        if self._sequence == self.MAX_SEQUENCE:
            self._sequence = self.MIN_SEQUENCE
        else:
            self._sequence += 1
        return self._sequence