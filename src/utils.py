# ebpH --  An eBPF intrusion detection program.
# -------  Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebphd <COMMAND>
#
# Licensed under GPL v2 License

import os, sys
import json
from functools import wraps

# Return the path of a file relative to the root dir of this project (above src)
def path(f):
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir,".."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path

# Decorated functions take the specified lock before invoking and release it after returning
def locks(lock):
    def decorator(func):
        @wraps(func)
        def inner(*args, **kwargs):
            lock.acquire()
            ret =  func(*args, **kwargs)
            lock.release()
            return ret
        return inner
    return decorator

# Serialize json
def to_json_bytes(x, encoding='utf-8'):
    return json.dumps(x).encode(encoding)

# Unserialize json
def from_json_bytes(x, encoding='utf-8'):
    return json.loads(x.decode(encoding))
