"""
Python implementation of a Sysinternals Dbgview client
Compatible with Python 3.5+

Copyright (c) 2019 Maxime Raynaud. All rights reserved.  
Licensed under the MIT License. See LICENSE file in the
project root for full license information.
"""
import io
import sys
import ctypes
import argparse
import asyncio
import struct
import logging
import weakref
import functools
from datetime import datetime

logger = logging.getLogger(__name__)

# Windows FILETIME
EPOCH_AS_FILETIME = 116444736000000000
HUNDREDS_OF_NANOSECONDS = 10000000


# Helpers
def _pack_dword(value):
    return struct.pack("I", value)


def _unpack_byte(binary):
    return struct.unpack("B", binary)[0]


def _unpack_dword(binary):
    return struct.unpack("I", binary)[0]


def _unpack_qword(binary):
    return struct.unpack("Q", binary)[0]


def _filetime_to_dt(ft):
    # Get seconds and remainder in terms of Unix epoch
    (s, ns100) = divmod(ft - EPOCH_AS_FILETIME, HUNDREDS_OF_NANOSECONDS)
    # Convert to datetime object
    dt = datetime.utcfromtimestamp(s)
    # Add remainder in as microseconds
    dt = dt.replace(microsecond=(ns100 // 10))
    return dt


class DbgviewException(Exception):
    pass


class DbgviewSignalException(DbgviewException):
    pass


class _SignalMethod(object):
    """
    Inspired by https://gist.github.com/Ahuge/2175bc17354290cdd45f3e56ad279498
    """

    def __init__(self, fn):
        self._fn = fn
        self._connections = set()
        # https://stackoverflow.com/questions/6394511
        functools.update_wrapper(self, fn)

    def __call__(self, *args, **kwargs):
        return self.emit(*args, **kwargs)

    def connect(self, callback):
        weak_owner = None
        weak_callback = weakref.ref(callback)
        try:
            weak_owner = weakref.ref(callback.im_self)
            weak_callback = weakref.ref(callback.im_func)
        except AttributeError:
            pass
        self._connections.add((weak_owner, weak_callback))

    def disconnect(self, callback):
        for weak_owner, weak_callback in self._connections:
            if ((weak_callback() is callback) or
                (hasattr(callback, "im_func") and
                 weak_callback() is callback.im_func)):
                self._connections.remove((weak_owner, weak_callback))
                return
        raise SignalException("Callable not found!")

    def emit(self, *args, **kwargs):
        for weak_owner, weak_callback in self._connections:
            callback = weak_callback()
            if callback is None:
                continue

            owner = weak_owner() if weak_owner else None
            if owner:
                callback(owner, *args, **kwargs)
            else:
                callback(*args, **kwargs)


def signal(fn):
    return _SignalMethod(fn)


class DbgviewClientProtocolException(DbgviewException):
    pass


class DbgviewClientProtocol(asyncio.Protocol):
    """
    Inspired by DbgviewReader.cpp (https://github.com/CobaltFusion/DebugViewPP)
    """

    _BASE = 0x83050000
    _CAPTURE_UNKNOWN_ENABLE = _BASE + 0x08
    _CAPTURE_UNKNOWN_DISABLE = _BASE + 0x0C
    _CAPTURE_KERNEL_ENABLE = _BASE
    _CAPTURE_KERNEL_DISABLE = _BASE + 0x04
    _CAPTURE_PASSTHROUGH_ENABLE = _BASE + 0x10
    _CAPTURE_PASSTHROUGH_DISABLE = _BASE + 0x14
    _CAPTURE_WIN32_ENABLE = _BASE + 0x18
    _CAPTURE_WIN32_DISABLE = _BASE + 0x1c
    _REQUEST_QUERY_PERFORMANCE_FREQ = _BASE + 0x28

    _PID_BEGIN_DELIMITER = b"\x01"
    _PID_END_DELIMITER = b"\x02"

    def __init__(self,
                 loop=None,
                 capture_kernel=False,
                 passthrough_kernel=False,
                 capture_win32=True):
        if loop is not None:
            self._loop = loop
        else:
            self._loop = asyncio.new_event_loop()

        self._capture_kernel = capture_kernel
        self._passthrough_kernel = passthrough_kernel
        self._capture_win32 = capture_win32

        self._transport = None
        self._saved_exc = None

        self._reset()

    def _reset(self):
        self._recv_handler = lambda: None

        self._inbuf = b""

        if self._transport is not None:
            self._transport.close()
            self._transport = None

        self._sock = None
        self._peer_addr = None

        self._t0 = None
        self._freq = None
        self._timer_unit = None

    @property
    def saved_exception(self):
        return self._saved_exc

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        try:
            self.close()
        except RuntimeError as exc:
            if exc.args[0] == 'Event loop is closed':
                pass
            else:
                raise

    def _send(self, data):
        if self._transport:
            self._transport.write(data)

    def _force_close(self, exc):
        if not self._saved_exc:
            self._saved_exc = exc

        if not self._transport:
            return

        self._transport.abort()
        self._transport = None

    def _send_query_freq(self):
        logger.debug("send_query_freq")
        self._recv_handler = self._recv_freq
        self._send(_pack_dword(self._REQUEST_QUERY_PERFORMANCE_FREQ))

    def _recv_freq(self):
        if len(self._inbuf) < 4:
            return False

        self._freq = _unpack_dword(self._inbuf[:4])
        logger.debug("received_freq: {}".format(self._freq))
        self._inbuf = self._inbuf[4:]
        self._timer_unit = 1 / float(self._freq)

        self._send_capture_settings()

    def _send_capture_settings(self):
        logger.debug("send_capture_settings")
        self._recv_handler = self._recv_messages
        if self._passthrough_kernel:
            self._send(_pack_dword(self._CAPTURE_PASSTHROUGH_ENABLE))
        else:
            self._send(_pack_dword(self._CAPTURE_PASSTHROUGH_DISABLE))

        if self._capture_kernel:
            self._send(_pack_dword(self._CAPTURE_KERNEL_ENABLE))
        else:
            self._send(_pack_dword(self._CAPTURE_KERNEL_DISABLE))

        if self._capture_win32:
            self._send(_pack_dword(self._CAPTURE_WIN32_ENABLE))
        else:
            self._send(_pack_dword(self._CAPTURE_WIN32_DISABLE))

    def _recv_messages(self):
        if len(self._inbuf) < 4:
            # Not enough data
            return False

        messages_size = _unpack_dword(self._inbuf[:4])
        if (messages_size == 0) or (messages_size >= 0x7fffffff):
            # Invalid or empty data
            self._inbuf = self._inbuf[4:]
            return True

        if len(self._inbuf) < (4 + messages_size):
            # Not enough data
            return False

        messages = self._inbuf[4:4 + messages_size]
        self._inbuf = self._inbuf[4 + messages_size:]

        self._process_messages(io.BytesIO(messages))
        return True

    @signal
    def on_message(self, lineno, time, offs, pid, msg):
        """Signal sent whenever a message is received."""
        pass

    def _process_messages(self, data):
        while True:
            buf = data.read(4)
            if len(buf) < 4:
                # Reached end of data
                break

            # Line number
            lineno = _unpack_dword(buf)
            logger.debug("lineno: {}".format(lineno))

            # Time
            buf = data.read(8)
            try:
                time = _filetime_to_dt(_unpack_qword(buf))
            except Exception as e:
                logger.debug("caught exception during time "
                             "interpretation: {}".format(e))
                time = datetime.min
            logger.debug("time: {}".format(time))

            # Offset from first message
            offset = _unpack_qword(data.read(8))
            if not self._t0:
                self._t0 = offset
            offset = (offset - self._t0) * self._timer_unit
            logger.debug("offset: {}".format(offset))

            # Message
            msg = []

            # Message can start with PID between delimiters
            buf = data.read(1)
            if buf == self._PID_BEGIN_DELIMITER:
                # PID
                pid = []
                # Maximum PID is 0xFFFFFFFC
                max_pid_len = 4
                while len(pid) <= max_pid_len:
                    buf = data.read(1)
                    if buf == self._PID_END_DELIMITER:
                        break
                    pid.append(str(buf, "ascii"))
                # Discard one leading space
                data.read(1)
                # Turn array into int
                pid = int("".join(pid))
                logger.debug("pid: {}".format(pid))

            # Maximum message length is DBWIN_BUFFER size
            max_len = 4096
            while len(msg) <= max_len:
                buf = data.read(1)
                if buf == b'' or buf == b'\0':
                    break
                msg.append(buf.decode("ascii"))

            # Turn array into string
            msg = "".join(msg).strip()
            logger.debug("message: {}".format(msg))

            # discard bytes until 4-bytes alignment
            remainder = data.tell() % 4
            if remainder > 0:
                data.read(4 - remainder)

            self.on_message(lineno, time, offset, pid, msg)

    def connection_made(self, transport):
        logger.info("connected!")
        self._transport = transport
        self._sock = transport.get_extra_info('socket')

        peername = transport.get_extra_info('peername')
        self._peer_addr = peername[0] if peername else None

        # Make synchronous handshake on connection_made
        self._send_query_freq()
        self._sock.setblocking(1)
        data = self._sock.recv(4)  # care! blocking
        self._sock.setblocking(0)
        self.data_received(data)

    def data_received(self, data):
        if data:
            self._inbuf += data

            try:
                while self._inbuf and self._recv_handler():
                    pass
            except DbgviewClientProtocolException as exc:
                self._force_close(exc)
            except Exception:
                self.internal_error()

    def internal_error(self, exc_info=None):
        if not exc_info:
            exc_info = sys.exc_info()

        logger.error("uncaught exception", exc_info=exc_info)
        self._force_close(exc_info[1])

    def eof_received(self):
        self.connection_lost()

    def connection_lost(self, exc=None):
        logger.debug("connection_lost")
        if exc is None and self._transport:
            exc = DbgviewClientProtocolException("Connection lost")
        self._force_close(exc)
        self._reset()
        self._loop.stop()
        raise exc


def dbgview_create_connection(loop,
                              remote_addr,
                              capture_kernel=False,
                              passthrough_kernel=False,
                              capture_win32=True,
                              on_message_cb=None):

    def client_factory():
        proto = DbgviewClientProtocol(loop, capture_kernel, passthrough_kernel,
                                      capture_win32)
        if on_message_cb is not None:
            proto.on_message.connect(on_message_cb)
        return proto

    logger.debug("creating client")
    coro = loop.create_connection(client_factory, remote_addr, 2020)
    return loop.run_until_complete(coro)


def dbgview_print(fmt):
    ctypes.windll.kernel32.OutputDebugStringW(fmt)


def _dbgview_print_cmd(args):
    dbgview_print(args.line)


def dbgview_connect(remote_addr):
    loop = asyncio.get_event_loop()

    def output_message(lineno, time, offs, pid, msg):
        if pid is not None:
            sys.stdout.write(
                "[{lineno}][{time}][{offs:.5f}][{pid}] {msg}\n".format(
                    lineno=lineno, time=time, offs=offs, pid=pid, msg=msg))
        else:
            sys.stdout.write("[{lineno}][{time}][{offs}] {msg}\n".format(
                lineno=lineno, time=time, offs=offs, msg=msg))
        sys.stdout.flush()

    transport, protocol = dbgview_create_connection(
        loop, remote_addr, on_message_cb=output_message)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("caught keyboard interrupt")
    finally:
        transport.abort()
        loop.close()

    if protocol.saved_exception is not None:
        raise protocol.saved_exception


def _dbgview_connect_cmd(args):
    dbgview_connect(args.remote_addr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v",
                        "--verbose",
                        action="store_true",
                        help="increase output verbosity")
    subparsers = parser.add_subparsers()

    if sys.platform == "win32":
        # Print (Windows-only)
        print_parser = subparsers.add_parser(
            "print", help="sends a string to the debugger for display")
        print_parser.add_argument('line', type=str)
        print_parser.set_defaults(func=_dbgview_print_cmd)

    # Connect to remote dbgview
    connect_parser = subparsers.add_parser(
        'connect',
        help="connects to a remote dbgview agent and listens for messages")
    connect_parser.add_argument('remote_addr')
    connect_parser.set_defaults(func=_dbgview_connect_cmd)

    args = parser.parse_args()

    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level)

    if "func" not in args:
        parser.print_usage()
        sys.exit(-1)

    args.func(args)


if __name__ == "__main__":
    main()
