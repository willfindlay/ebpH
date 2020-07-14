import sys
import json
from argparse import Namespace
from typing import Dict

import requests
from requests.exceptions import ConnectionError

from ebph import defs

header = False

def format_comm(comm):
    return comm if len(comm) < 20 else ''.join(['...', comm[-17:]])

def print_profile_information(profile: Dict):
    comm = format_comm(profile["exe"])
    status = profile['status']
    status = status.split('EBPH_PROFILE_STATUS.')[1].lower()
    anomalies = profile['anomaly_count']
    train_count = profile['train_count']
    last_mod_count = profile['last_mod_count']
    normal_time = profile['normal_time']

    global header
    if not header:
        print(f"{'COMM':<20} {'STATUS':<16} {'TRAIN_COUNT':>12} {'LAST_MOD':>12} {'ANOMALIES':>12}   {'NORMAL TIME':<16}")
        header = True

    print(f"{comm:<20} {status:<16} {train_count:>12} {last_mod_count:>12} "
            f"{anomalies:>12}   {normal_time:<16}")

def print_process_information(process: Dict, show_tid: bool):
    # Process stuff
    pid = process['pid']
    tid = process['tid']
    process_count = process['count']
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
        print(f"{process_part} {'COMM':<20} {'STATUS':<16} {'TRAIN_COUNT':>12} {'LAST_MOD':>12} {'ANOMALIES':>12}   {'NORMAL TIME':<16}")
        header = True

    if show_tid:
        process_part = f"{pid:<8} {tid:<8}"
    else:
        process_part = f"{pid:<8}"

    print(f"{process_part} {comm:<20} {status:<16} {train_count:>12} {last_mod_count:>12} "
            f"{anomalies:>12}   {normal_time:<16}")


def main(args: Namespace):
    if args.profiles:
        try:
            res = requests.get(f'http://localhost:{defs.EBPH_PORT}/profiles')
        except ConnectionError:
            print('Unable to connect to ebpH daemon!', file=sys.stderr)
            sys.exit(-1)
        if res.status_code != 200:
            print('Unable to get profiles!', file=sys.stderr)
        for p in sorted(json.loads(res.content), key=lambda p: p['exe']):
            print_profile_information(p)
    else:
        try:
            res = requests.get(f'http://localhost:{defs.EBPH_PORT}/processes')
        except ConnectionError:
            print('Unable to connect to ebpH daemon!', file=sys.stderr)
            sys.exit(-1)
        if res.status_code != 200:
            print('Unable to get processes!', file=sys.stderr)
        processes = json.loads(res.content)
        if not args.threads:
            processes = [p for p in processes if p['pid'] == p['tid']]
        for p in sorted(processes, key=lambda p: (p['pid'], p['tid'])):
            print_process_information(p, args.threads)
