"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay 
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

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

    Implements ebph admin.

    2020-Jul-13  William Findlay  Created this.
"""

import sys
from argparse import Namespace
from typing import Dict, Callable
import subprocess
from pprint import pprint

import requests
from requests.exceptions import ConnectionError

from ebph.structs import EBPH_PROFILE_STATUS, EBPH_SETTINGS
from ebph import defs
from ebph.utils import fail_with, request_or_die

commands = {}

def command(name: str) -> Callable:
    """
    Register an ebph admin command.
    """
    def inner(func: Callable) -> Callable:
        def wrapper(args) -> None:
            func(args)

        global commands
        commands[name] = wrapper
    return inner

@command('start')
def start(args: Namespace) -> None:
    try:
        subprocess.check_call(['ebphd', 'start'])
    except subprocess.CalledProcessError:
        fail_with('Failed to start the daemon. Check logs for more info.')

@command('stop')
def stop(args: Namespace) -> None:
    try:
        subprocess.check_call(['ebphd', 'stop'])
    except subprocess.CalledProcessError:
        fail_with('Failed to stop the daemon. Check logs for more info.')

@command('restart')
def restart(args: Namespace) -> None:
    try:
        subprocess.check_call(['ebphd', 'restart'])
    except subprocess.CalledProcessError:
        fail_with('Failed to restart the daemon. Check logs for more info.')

@command('save')
def save(args: Namespace) -> None:
    res = request_or_die(requests.put, f'/profiles/save', 'Unable to save profiles')
    body = res.json()
    saved = body['saved']
    err = body['error']
    print(f'Saved {saved} profiles, with {err} errors.')

@command('load')
def load(args: Namespace) -> None:
    res = request_or_die(requests.put, f'/profiles/load', 'Unable to load profiles')
    body = res.json()
    loaded = body['loaded']
    err = body['error']
    print(f'Loaded {loaded} profiles, with {err} errors.')

@command('status')
def status(args: Namespace) -> None:
    res = request_or_die(requests.get, f'/status', 'Unable to get status')
    body = res.json()
    for k, v in body.items():
        keystr = f'{k}:'
        print(f'{keystr:<16} {v}')

@command('set')
def set(args: Namespace) -> None:
    setting = EBPH_SETTINGS(args.category)
    value = args.value
    res = request_or_die(requests.put, f'/settings/{setting}/{value}', f'Failed to change {setting.name} to {value}')
    print(f'Changed {setting.name} to {value}.')

@command('normalize')
def normalize(args: Namespace) -> None:
    if args.profile:
        res = request_or_die(requests.put, f'/profiles/exe/{args.profile}/normalize', f'Unable to normalize profile at exe {args.profile}')
    elif args.pid:
        res = request_or_die(requests.put, f'/processes/pid/{args.pid}/normalize', f'Unable to normalize profile at pid {args.pid}')
    else:
        raise NotImplementedError('No PID or profile supplied.')
    body = res.json()
    if args.profile:
        print(f'Normalized profile {body["exe"]} successfully.')
    else:
        print(f'Normalized PID {body["pid"]} ({body["profile"]["exe"]}) successfully.')

@command('sensitize')
def sensitize(args: Namespace) -> None:
    if args.profile:
        res = request_or_die(requests.put, f'/profiles/exe/{args.profile}/sensitize', f'Unable to sensitize profile at exe {args.profile}')
    elif args.pid:
        res = request_or_die(requests.put, f'/processes/pid/{args.pid}/sensitize', f'Unable to sensitize profile at pid {args.pid}')
    else:
        raise NotImplementedError('No PID or profile supplied.')
    body = res.json()
    if args.profile:
        print(f'Sensitized profile {body["exe"]} successfully.')
    else:
        print(f'Sensitized PID {body["pid"]} ({body["profile"]["exe"]}) successfully.')

@command('tolerize')
def tolerize(args: Namespace) -> None:
    if args.profile:
        res = request_or_die(requests.put, f'/profiles/exe/{args.profile}/tolerize', f'Unable to tolerize profile at exe {args.profile}')
    elif args.pid:
        res = request_or_die(requests.put, f'/processes/pid/{args.pid}/tolerize', f'Unable to tolerize profile at pid {args.pid}')
    else:
        raise NotImplementedError('No PID or profile supplied.')
    body = res.json()
    if args.profile:
        print(f'Tolerized profile {body["exe"]} successfully.')
    else:
        print(f'Tolerized PID {body["pid"]} ({body["profile"]["exe"]}) successfully.')

def main(args: Namespace) -> None:
    if args.admin_command not in commands.keys():
        fail_with(f'Invalid command: {args.admin_command}!')
    commands[args.admin_command](args)
