import sys
import json
from argparse import Namespace
from typing import Dict
import subprocess
from pprint import pformat

import requests
from requests.exceptions import ConnectionError

from ebph.structs import EBPH_PROFILE_STATUS, EBPH_SETTINGS
from ebph import defs

header = False

def main(args: Namespace):
    if args.admin_command == 'start':
        subprocess.Popen(['ebphd', 'start']).wait()
    if args.admin_command == 'stop':
        subprocess.Popen(['ebphd', 'stop']).wait()
    if args.admin_command == 'restart':
        subprocess.Popen(['ebphd', 'restart']).wait()
    if args.admin_command == 'set':
        setting = EBPH_SETTINGS(args.category)
        value = args.value
        try:
            res = requests.put(f'http://localhost:{defs.EBPH_PORT}/settings/{setting}/{value}')
        except requests.ConnectionError:
            print('Unable to connect to ebpH daemon!', file=sys.stderr)
        if res.status_code != 200:
            print(f'Failed to change {setting.name} to {value}!', file=sys.stderr)
            sys.exit(-1)
        print(f'Changed {setting.name} to {value}.')
