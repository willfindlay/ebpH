#! /usr/bin/env python3

import os

def init():
    global PROFILE_DIR
    global LOADER_PATH

    # directory in which profiles are stored
    PROFILE_DIR = "/var/lib/pH/profiles"
    # path of profile loader executable
    LOADER_PATH = os.path.abspath("profile_loader")
