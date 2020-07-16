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

    Provides several utility functions that don't really fit elsewhere.

    2020-Jul-13  William Findlay  Created this.
"""

import os
import sys
from datetime import datetime, timedelta

def project_path(f):
    """
    Return the path of a file relative to the root dir of this project (parent directory of "src").
    """
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir, ".."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path

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

def ns_to_str(ns: int):
    dt = datetime.fromtimestamp(ns // 1000000000)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def ns_to_delta_str(ns: int):
    td = timedelta(seconds=(ns // 1000000000))
    return str(td)

def which(program):
     import os

     def is_exe(fpath):
         return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

     fpath, _fname = os.path.split(program)
     if fpath:
         if is_exe(program):
             return program
     else:
         for path in os.environ["PATH"].split(os.pathsep):
             exe_file = os.path.join(path, program)
             if is_exe(exe_file):
                 return exe_file

     return None

def calculate_profile_key(fpath):
    s = os.stat(fpath)
    st_dev = s.st_dev
    st_ino = s.st_ino
    return st_dev << 32 | st_ino

