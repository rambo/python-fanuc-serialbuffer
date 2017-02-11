from .common import FanucError



class MessageParseError(FanucError):
    pass



class MessageIntegrityError(FanucError):
    pass



class FanucMessage(object)
    """The top-level message packet container"""
    msg_checksum = 0
    msg_command = b'SYN'
    msg_data = b''
    msg_end = b'\r'

    def __init__(self, parsemsg=None):
        if parsemsg:
            self.parse_message(parsemsg)

    def parse_message(self, msg):
        self.msg_checksum = int(msg[0:2], 16)
        self.msg_command = msg[3:6]
        self.msg_data = msg[6:-1]
        self.msg_end = msg[-1]
        self.validatemsg_checksum()
        raise NotImplementedError()

    def validatemsg_checksum(self):
        if self.calculatemsg_checksum() != self.msg_checksum:
            raise MessageIntegrityError("Checksum mismatch")

    def calculatemsg_checksum(self, setsum=False):
        raise NotImplementedError()
        if setsum:
            self.msg_checksum = result

    def to_bytes(self):
        self.calculatemsg_checksum(True)
        self.pack_data()
        raise NotImplementedError()

    def parse_data(self, data=None):
        raise NotImplementedError("Must be implemented in subclasses")

    def pack_data(self):
        raise NotImplementedError("Must be implemented in subclasses")



class SATMessage(FanucMessage)
    """Status message from buffer to host"""
    rmsts = 0
    bufferstatus = 0
    alarmreason = 0
    bufferedbytes = 0
    emptyarea_limit = 2000
    overrun_limit = 50
    retry_limit = 10
    polling_interval = 5
    timeout = 20
    min_byte_interval = 10
    min_rxtx_switchtime = 100
    wait_time = 5
    code_to_convert = 0
    code_convert_to = 0
    protocolversion = 0

    def parse_data(self, data=None):
        if not data:
            data = self.msg_data
        self.rmsts = int(data[0], 16)
        self.bufferstatus = int(data[1], 16)
        self.alarmreason = int(data[2], 16)
        self.bufferedbytes = int(data[4:8], 16)
        self.emptyarea_limit = int(data[8:12], 16)
        self.overrun_limit = int(data[12:16], 16)
        self.retry_limit = int(data[16:20], 16)
        self.polling_interval = int(data[20:24], 16)
        self.timeout = int(data[24:28], 16)
        self.min_byte_interval = int(data[28:32], 16)
        self.min_rxtx_switchtime = int(data[32:36], 16)
        self.wait_time = int(data[36:40], 16)
        self.code_to_convert = int(data[44:46], 16)
        self.code_convert_to = int(data[46:48], 16)
        self.protocolversion = int(data[54:56], 16)

    def pack_data(self):
        raise FanucError("SAT messages are receive-only")



class SETMessage(SATMessage):
    """Parameter update message from host to buffer"""

    def pack_data(self):
        self.msg_command = b'SET'
        # Initialize as all zeros
        self.msg_data = bytes([ord('0') for x in range(72)])
        # TODO: Set the co
        raise NotImplementedError("not done")



class SDIMessage(FanucMessage)
    """Contents of DI (PMC address G239)"""
    content = 0

    def parse_data(self, data=None):
        if not data:
            data = self.msg_data
        self.content = int(data[0:2], 16)

    def pack_data(self):
        raise FanucError("SDI messages are receive-only")



class SDOMessage(SDIMessage)
    """Contents of DO (PMC address G289)"""

    def pack_data(self):
        self.msg_command = b'SDO'
        self.msg_data = bytearray(b'%02X' % self.content)



class RTYMessage(FanucMessage)
    """Retry"""
    reason = 0

    CHECKSUM_ERROR = 1
    OVERRUN = 3

    def parse_data(self, data=None):
        if not data:
            data = self.msg_data
        # FIXME: doublecheck if the value here is hexadecimal (like everything else) or raw
        self.reason = int(data[0], 16)

    def pack_data(self):
        self.msg_command = b'RTY'
        self.msg_data = bytearray(b'%01X' % self.reason)



class NoDataMessage(FanucMessage)
    def pack_data(self):
        self.msg_data = b''
