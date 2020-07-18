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

    Provides several utility functions that don't really fit elsewhere.

    2020-Jul-13  William Findlay  Created this.
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Callable, Iterator, Union

import requests

def project_path(f: str) -> str:
    """
    Return the path of a file relative to the root dir of this project (parent directory of "src").
    """
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir, ".."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path

def read_chunks(f: str, size: int = 1024) -> Iterator[str]:
    """
    Read a file in chunks.
    Default chunk size is 1024.
    """
    while 1:
        data = f.read(size)
        if not data:
            break
        yield data

def ns_to_str(ns: int) -> str:
    dt = datetime.fromtimestamp(ns // 1000000000)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def ns_to_delta_str(ns: int) -> str:
    td = timedelta(seconds=(ns // 1000000000))
    return str(td)

def which(program: str) -> Union[str, None]:
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

def calculate_profile_key(fpath: str) -> int:
    s = os.stat(fpath)
    st_dev = s.st_dev
    st_ino = s.st_ino
    return st_dev << 32 | st_ino

def fail_with(err: str) -> None:
    print(err, file=sys.stderr)
    sys.exit(-1)

def request_or_die(req_method: Callable, url: str, fail_message:str = 'Operation failed',
        data=None, json=None, **kwargs) -> requests.Response:
    """
    Either make a request, or die with an error message.
    """
    from ebph.defs import EBPH_PORT
    try:
        url = f'http://localhost:{EBPH_PORT}{url}'
        res = req_method(url, data=data, json=json, **kwargs)
        if res.status_code != 200:
            try:
                fail_with(f'{fail_message}: {res.json()["detail"]}')
            except KeyError:
                fail_with(fail_message)
        return res
    except requests.ConnectTimeout:
        fail_with('Connection to ebpH daemon timed out during request!')
    except requests.ConnectionError:
        fail_with('Unable to connect to ebpH daemon!')
