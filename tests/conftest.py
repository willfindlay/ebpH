import os
import time
import logging
import threading

import pytest

from ebph.ebphd import parse_args
from ebph.logger import EBPHLoggerClass
from ebph.bpf_program import BPFProgram
from ebph import defs

NEWSEQ = EBPHLoggerClass.SEQUENCE

# Redirect profile saving to /tmp/ebph/profiles
defs.EBPH_DATA_DIR = '/tmp/ebph/profiles'
# Redirect logging to /tmp/ebph/log
defs.EBPH_LOG_DIR = '/tmp/ebph/log'

args = parse_args('--nodaemon'.split())
defs.init(args)

def loop_forever(bpf_program: BPFProgram):
    def inner():
        while 1:
            bpf_program.on_tick()
            time.sleep(defs.TICK_SLEEP)
    return inner

@pytest.fixture(scope='function')
def bpf_program(caplog):
    for f in os.listdir(defs.EBPH_DATA_DIR):
        os.unlink(os.path.join(defs.EBPH_DATA_DIR, f))

    # Set log level
    caplog.set_level(NEWSEQ)
    b = BPFProgram()

    thread = threading.Thread(target=loop_forever(b))
    thread.daemon = True
    thread.start()

    yield b

    b.on_tick()
    b._cleanup
