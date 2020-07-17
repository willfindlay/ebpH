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

    Implements ebph ps.

    2020-Jul-13  William Findlay  Created this.
"""

import sys
from argparse import Namespace
from typing import Dict

import requests
from requests.exceptions import ConnectionError

from ebph.utils import request_or_die
from ebph import defs

header = False

def format_comm(comm: str) -> str:
    return comm if len(comm) < 20 else ''.join(['...', comm[-17:]])

def print_profile_information(profile: Dict) -> None:
    comm = format_comm(profile["exe"])
    status = profile['status']
    status = status.split('EBPH_PROFILE_STATUS.')[1].lower()
    anomalies = profile['anomaly_count']
    train_count = profile['train_count']
    last_mod_count = profile['last_mod_count']
    normal_time = profile['normal_time']

    global header
    if not header:
        print(f"{'COMM':<20} {'STATUS':<16} {'TRAIN_COUNT':>12} {'LAST_MOD':>12} "
                f"{'ANOMALIES':>12}   {'NORMAL TIME':<16}")
        header = True

    print(f"{comm:<20} {status:<16} {train_count:>12} {last_mod_count:>12} "
            f"{anomalies:>12}   {normal_time:<16}")

def print_process_information(process: Dict, show_tid: bool) -> None:
    # Process stuff
    pid = process['pid']
    tid = process['tid']
    # Profile stuff
    profile = process['profile']
    comm = format_comm(profile["exe"])
    status = profile['status']
    status = status.split('EBPH_PROFILE_STATUS.')[1].lower()
    anomalies = profile['anomaly_count']
    train_count = profile['train_count']
    last_mod_count = profile['last_mod_count']
    normal_time = profile['normal_time']

    if show_tid:
        process_part = f"{'PID':<8} {'TID':<8}"
    else:
        process_part = f"{'PID':<8}"

    global header
    if not header:
        print(f"{process_part} {'COMM':<20} {'STATUS':<16} {'TRAIN_COUNT':>12} "
                f"{'LAST_MOD':>12} {'ANOMALIES':>12}   {'NORMAL TIME':<16}")
        header = True

    if show_tid:
        process_part = f"{pid:<8} {tid:<8}"
    else:
        process_part = f"{pid:<8}"

    print(f"{process_part} {comm:<20} {status:<16} {train_count:>12} {last_mod_count:>12} "
            f"{anomalies:>12}   {normal_time:<16}")


def main(args: Namespace) -> None:
    if args.profiles:
        res = request_or_die(requests.get, '/profiles', 'Unable to get profiles')
        for p in sorted(res.json(), key=lambda p: p['exe']):
            print_profile_information(p)
    else:
        res = request_or_die(requests.get, '/processes', 'Unable to get processes')
        processes = res.json()
        if not args.threads:
            processes = [p for p in processes if p['pid'] == p['tid']]
        for p in sorted(processes, key=lambda p: (p['pid'], p['tid'])):
            print_process_information(p, args.threads)
