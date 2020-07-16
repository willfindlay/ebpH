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
