#! /usr/bin/env python3

import os

def path(f):
    path = f"{os.path.dirname(__file__)}/{f}"
    return path

def init():
    global PROFILE_DIR
    global LOADER_PATH
    global DEFS_H
    global PROFILES_H

    # directory in which profiles are stored
    PROFILE_DIR = "/var/lib/pH/profiles"
    # path of profile loader executable
    LOADER_PATH = path("ebpH_command")
    DEFS_H = path("defs.h")
    PROFILES_H = path("profiles.h")
