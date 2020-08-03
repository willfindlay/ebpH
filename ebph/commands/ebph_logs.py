"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

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

    Implements ebph ps.

    2020-Jul-13  William Findlay  Created this.
"""

import os
from argparse import Namespace

from ebph import defs
from ebph.logger import color_log

def main(args: Namespace) -> None:
    logfile = os.path.join(defs.LOG_DIR, 'ebph.log')

    with open(logfile, 'r') as f:
        for line in f:
            try:
                print(color_log(line))
            except IOError:
                pass
