import os, sys

from config import Config

def path(f):
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir,".."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path
