import os
from bcc import USDT
import ctypes as ct
from ctypes.util import find_library
from typing import get_type_hints, List, Any

from ebph import defs
from ebph.logger import get_logger

logger = get_logger()

libebph = ct.CDLL(defs.LIBEBPH, use_errno=True)

usdt_context = USDT(pid=os.getpid())

def command(func):
    """
    A decorator that allows a function to provide an interface into a libebph
    command of the same name. Types are determined using Python type hints.
    """
    name = func.__name__
    th = get_type_hints(func)
    argtypes = [v for k, v in th.items() if k != 'return']
    try:
        restype = th['return']
    except KeyError:
        restype = None
    @staticmethod
    def wrapper(*args, **kwargs):
        return getattr(libebph, name)(*args, **kwargs)
    getattr(libebph, name).argtypes = argtypes
    getattr(libebph, name).restype = restype
    usdt_context.enable_probe_or_bail(name, 'command_' + name)
    logger.info(f'Registering USDT probe {name} -> command_{name}...')
    logger.debug(f'name={name}, argtypes={argtypes}, restype={restype}')
    return wrapper

class Lib:
    """
    Exports libebph commands, inferring ctypes argtypes and restypes
    using Python type hints. All @command methods are static methods.
    """
    usdt_context = usdt_context

    @command
    def set_setting(key: ct.c_int, value: ct.c_uint64) -> ct.c_int:
        pass

