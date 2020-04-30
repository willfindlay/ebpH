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
from functools import wraps

import bcc.syscall

def path(f):
    """
    Return the path of a file relative to the root dir of this project (parent directory of "src").
    """
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir, ".."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path

# Config cannot be imported earlier than this
from ebpH import defs

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
