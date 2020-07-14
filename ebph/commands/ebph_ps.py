import sys
import json
from argparse import Namespace

import requests

from ebph import defs

header = False

def format_comm(comm):
    return comm if len(comm) < 16 else ''.join(['...', comm[:-13]])

def print_profile_information(profile):
    comm = format_comm(profile["exe"])
    status = profile['status']
    status = status.split('EBPH_PROFILE_STATUS.')[1]
    anomalies = profile['anomaly_count']
    train_count = profile['train_count']
    last_mod_count = profile['last_mod_count']
    normal_time = profile['normal_time']

    global header
    if not header:
        print(f"{'COMM':<16} {'STATUS':<20} {'TRAIN_COUNT':>12} {'LAST_MOD':>12} {'ANOMALIES':>12} {'NORMAL TIME':<16}")
        header = True

    print(f"{comm:<16} {status:<20} {train_count:>12} {last_mod_count:>12} "
            f"{anomalies:>12} {normal_time:<16}")


def main(args: Namespace):
    if args.profiles:
        res = requests.get(f'http://localhost:{defs.EBPH_PORT}/profiles')
        if res.status_code != 200:
            print('Unable to get profiles', file=sys.stderr)
        for p in json.loads(res.content):
            print_profile_information(p)
    else:
        res = requests.get(f'http://localhost:{defs.EBPH_PORT}/processes')

    if args.profiles:
        print('profiles')
    elif args.threads:
        print('threads')
    else:
        print('processes')
