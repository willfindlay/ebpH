import sys
import json
from argparse import Namespace
from typing import Dict, Callable
import subprocess

import requests
from requests.exceptions import ConnectionError

from ebph.structs import EBPH_PROFILE_STATUS, EBPH_SETTINGS
from ebph import defs

commands = {}

def command(name: str):
    def inner(func: Callable):
        def wrapper(args):
            func(args)

        global commands
        commands[name] = wrapper
    return inner

@command('start')
def start(args: Namespace):
    subprocess.Popen(['ebphd', 'start']).wait()

@command('stop')
def stop(args: Namespace):
    subprocess.Popen(['ebphd', 'stop']).wait()

@command('restart')
def restart(args: Namespace):
    subprocess.Popen(['ebphd', 'restart']).wait()

@command('save')
def save(args: Namespace):
    try:
        res = requests.put(f'http://localhost:{defs.EBPH_PORT}/profiles/save')
    except requests.ConnectionError:
        print('Unable to connect to ebpH daemon!', file=sys.stderr)
        sys.exit(-1)
    res = json.loads(res.content)
    saved = res['saved']
    err = res['error']
    print(f'Saved {saved} profiles, with {err} errors.')

@command('load')
def load(args: Namespace):
    try:
        res = requests.put(f'http://localhost:{defs.EBPH_PORT}/profiles/load')
    except requests.ConnectionError:
        print('Unable to connect to ebpH daemon!', file=sys.stderr)
        sys.exit(-1)
    res = json.loads(res.content)
    loaded = res['loaded']
    err = res['error']
    print(f'Loaded {loaded} profiles, with {err} errors.')

@command('status')
def status(args: Namespace):
    raise NotImplementedError()

@command('set')
def set(args: Namespace):
    setting = EBPH_SETTINGS(args.category)
    value = args.value
    try:
        res = requests.put(f'http://localhost:{defs.EBPH_PORT}/settings/{setting}/{value}')
    except requests.ConnectionError:
        print('Unable to connect to ebpH daemon!', file=sys.stderr)
        sys.exit(-1)
    if res.status_code != 200:
        print(f'Failed to change {setting.name} to {value}!', file=sys.stderr)
        sys.exit(-1)
    print(f'Changed {setting.name} to {value}.')

@command('normalize')
def normalize(args: Namespace):
    raise NotImplementedError()

@command('sensitize')
def sensitize(args: Namespace):
    raise NotImplementedError()

@command('tolerize')
def tolerize(args: Namespace):
    raise NotImplementedError()

def main(args: Namespace):
    if args.admin_command not in commands.keys():
        print(f'Invalid command: {args.admin_command}!', file=sys.stderr)
        sys.exit(-1)
    commands[args.admin_command](args)
