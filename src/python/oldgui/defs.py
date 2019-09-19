#! /usr/bin/env python3
import os

# /project/dir/f
def path(f):
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir,"../../.."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path

def init():
    global PROFILE_DIR
    global LOADER_PATH
    global BPF_C
    global DEFS_H
    global PROFILES_H


    # directory in which profiles are stored
    PROFILE_DIR = "/var/lib/ebpH/profiles"

    # path of profile loader executable
    LOADER_PATH = path("ebpH_command")
    BPF_C = path("src/c/bpf.c")
    DEFS_H = path("src/c/defs.h")
    PROFILES_H = path("src/c/profiles.h")
