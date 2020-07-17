"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    Copyright (C) 2019-2020  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Provide a fixture for an ebpH bpf_program continuously calling on_tick.

    2020-Jul-16  William Findlay  Created this.
"""
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
