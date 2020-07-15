import sys
import json
from argparse import Namespace
from typing import Dict
import subprocess

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
