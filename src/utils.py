# ebpH  An eBPF intrusion detection program. Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# Licensed under GPL v2 License

import os, sys
import json
import time
import socket
from functools import wraps

import bcc.syscall

import config

def syscall_name(num: int):
    """
    Convert a system call number into a name.

    Args:
        num: system call number

    Return:
        Uppercase string system call name
    """
    name_bin = bcc.syscall.syscall_name(num)
    return name_bin.decode('utf-8').upper()

def setup_dir(d):
    """
    Make dirs if path does not exist.
    """
    if not os.path.exists(d):
        os.makedirs(d)

def path(f):
    """
    Return the path of a file relative to the root dir of this project (parent directory of "src").
    """
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir,".."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path

def locks(lock):
    """
    Decorated functions take the specified lock before invoking and release it after returning.
    Usage:
        @locks(the_lock)
        def func ...
    """
    def decorator(func):
        @wraps(func)
        def inner(*args, **kwargs):
            try:
                lock.acquire()
                ret =  func(*args, **kwargs)
            finally:
                lock.release()
            return ret
        return inner
    return decorator

def to_json_bytes(x, encoding='utf-8'):
    """
    Serialize json.
    """
    return json.dumps(x).encode(encoding)

def from_json_bytes(x, encoding='utf-8'):
    """
    Unserialize json.
    """
    return json.loads(x.decode(encoding))

def connect_to_socket():
    """
    Connect to ebpH's socket and return the corresponding socket object.
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(config.socket)
        return sock
    except ConnectionRefusedError:
        print(f"Unable to connect to {config.socket}... Is ebphd running?", file=sys.stderr)
        sys.exit(-1)

def receive_message(sock):
    """
    Receive a message of arbitrary length over a stream socket.
    Stop when we see config.sentinel or the connection closes (whichever happens first).
    """
    total_data = []
    sentinel = False

    while True:
        msg = sock.recv(config.socket_buff_size)
        if not msg.strip():
            break
        if bytes([msg[-1]]) == config.socket_sentinel:
            msg = msg[:-1]  # Remove sentinel from message
            sentinel = True # Mark that we have seen it
        total_data.append(msg)
        if sentinel:
            break

    return b"".join(total_data)

def send_message(sock, data):
    """
    Send a message over a stream socket, terminating automatically with config.sentinel.
    """
    sock.send(b"".join([data, config.socket_sentinel]))

def read_chunks(f, size=1024):
    """
    Read a file in chunks.
    Default chunk size is 1024.
    """
    while 1:
        data = f.read(size)
        if not data:
            break
        yield data

class LoggerWriter:
    """
    LoggerWriter

    A helper class for redirecting stdout and stderr to loggers.
    """
    def __init__(self, level):
        self.level = level
        self.message = ""

    def write(self, message):
        """
        Write each line of the message to the log.
        """
        self.message = ''.join([self.message, message])
        if message.endswith('\n'):
            self.flush()

    def flush(self):
        """
        Provide a dummy flush method.
        """
        for line in self.message.split('\n'):
            if not line.strip():
                continue
            self.level(line)
        self.message = ""
