#! /usr/bin/env python3

# ebpH --  An eBPF intrusion detection program.
# -------  Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebph <COMMAND>
#
# Licensed under GPL v2 License

import os, sys
import socket
import argparse
import struct
import subprocess
from functools import wraps
from copy import deepcopy

import config
config.init()
import json
from utils import to_json_bytes, from_json_bytes, receive_message, send_message

DESCRIPTION = """
Issue commands to ebpH and make queries about system state.
The ebpH daemon (ebphd) must be running in order to run this software.
"""

EPILOG = """
Example usage:
    sudo ebph-admin start  # Start the daemon
    sudo ebph-admin off    # Pause monitoring
    sudo ebph-admin status # Check system status
"""

EBPHD_PATH = os.path.join(config.project_path, 'ebphd')
EBPH_PS_PATH = os.path.join(config.project_path, 'ebph-ps')

commands = {}

def command(operation, command_arguments={}, ebph_func=None, use_socket=1):
    """
    Register a command that can be sent to ebpH.
    Commands that use sockets should accept a res argument that defaults to None.

    args:
        operation -> name of the command (should correspond to the command defined in argparse)
        command_arguments -> arguments that will be sent to the ebpH function that corresponds to the command
        ebph_func -> function that the daemon will be requested to run
        use_socket -> if set to 0, do something besides sending a command to the daemon
    """
    if not ebph_func:
        ebph_func = operation
    def decorator(func):
        @wraps(func)
        def inner():
            if use_socket:
                try:
                    # Connect to socket
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(config.socket)
                    # Form request
                    request = {'func': ebph_func, 'kwargs': command_arguments}
                    # Send request
                    send_message(sock, to_json_bytes(request))
                    # Handle response
                    res = receive_message(sock)
                    res = from_json_bytes(res)
                    # Server error
                    if res['code'] != 200:
                        print(f"Could not complete command \"{operation}\". System replied with code: {res['code']}.", file=sys.stderr)
                        sys.exit(-1)
                    return func(res)
                except ConnectionRefusedError:
                    print(f"Unable to connect to {config.socket}... Is ebphd running?", file=sys.stderr)
                finally:
                    sock.close()
            else:
                return func()
        # Append to commands list
        global commands
        commands[operation] = inner

        # Return the inner func
        return inner
    return decorator

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, prog="ebph-admin", epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    commands = parser.add_subparsers(title="possible commands", dest="command", required=1, metavar='command')
    start = commands.add_parser('start',
            help="Start the ebpH daemon.")

    restart = commands.add_parser('restart',
            help="Restart the ebpH daemon.")

    stop = commands.add_parser('stop',
            help="Stop the ebpH daemon.")

    on = commands.add_parser('on',
            help="Resume system monitoring.")

    off = commands.add_parser('off',
            help="Pause system monitoring without killing the daemon.")

    save_profiles = commands.add_parser('save',
            help="Save all profiles to disk. (This command only works if the daemon is allowed to save profiles).")

    status = commands.add_parser('status',
            help="Print ebpH status to stdout.")

    ps = commands.add_parser('ps',
            help="Run ebph-ps with the specified flags and arguments.")
    ps_options = ps.add_mutually_exclusive_group()
    ps_options.add_argument('-t', '--threads', action='store_true',
            help=f"Print all threads instead of just thread group leader.")
    ps_options.add_argument('-p', '--profiles', action='store_true',
            help=f"Print all profiles instead of active processes.")

    inspect = commands.add_parser('inspect',
            help="Inspect the profile with key <key>. Use ebph-ps -p to find profile keys.")
    inspect.add_argument('key',
            help="Key of the profile to inspect.")

    normalize = commands.add_parser('normalize',
            help='Start normal mode on process with tid <tid>.')
    normalize.add_argument('tid', type=int,
            help='Thread ID of the process to normalize. Can also be a PID.')

    #reset_profile = commands.add_parser('reset',
    #        help="Reset a profile.")
    #reset_profile.add_argument('key',
    #        help="Profile key that should be reset. You can find this with ebph-ps -p.")

    #delete_profile = commands.add_parser('delete-profile',
    #        help="Delete a profile.")
    #delete_profile.add_argument('key',
    #        help="Profile key that should be deleted. You can find this with ebph-ps -p.")

    args = parser.parse_args(args)

    # check for root
    if not (os.geteuid() == 0):
        parser.error("This script must be run with root privileges! Exiting.")

    return args

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    command_args = {k: v for k, v in vars(args).items() if k != 'command'}

    @command('start', use_socket=0)
    def start():
        """
        Start the daemon.
        """
        subprocess.run([EBPHD_PATH, 'start'])

    @command('restart', use_socket=0)
    def restart():
        subprocess.run([EBPHD_PATH, 'restart'])

    @command('stop', use_socket=0)
    def stop():
        """
        Stop the daemon.
        """
        subprocess.run([EBPHD_PATH, 'stop'])

    @command('on', ebph_func='start_monitoring')
    def on(res=None):
        """
        Start monitoring the system.
        """
        if res['message']:
            print(f"System is already being monitored.")
        else:
            print(f"System monitoring resumed.")

    @command('off', ebph_func='stop_monitoring')
    def off(res=None):
        """
        Stop monitoring the system.
        """
        if res['message']:
            print(f"System is not being monitored.")
        else:
            print(f"System monitoring paused.")

    @command('save', ebph_func='save_profiles')
    def save_profiles(res=None):
        """
        Force save profiles to disk.
        """
        print(res['message'])

    @command('status')
    def status(res=None):
        """
        Print ebphd status to the console.
        """
        print(f"{'ITEM':<16s} {'STATUS'}")
        for k, v in res['message'].items():
            print(f"{k:<16s} {v}")

    @command('ps', use_socket=0)
    def ps(res=None):
        """
        Invoke ebph-ps with the desired arguments.
        """
        flags = []
        if args.profiles:
            flags.append('-p')
        if args.threads:
            flags.append('-t')
        subprocess.run([EBPH_PS_PATH, *flags])

    @command('inspect', command_args, ebph_func='inspect_profile')
    def inspect(res=None):
        pass

    @command('normalize', command_args, ebph_func='normalize')
    def normalize(res=None):
        """
        Normalize profile attached to process <tid>.
        """
        print(res['message'])


    #@command('reset', command_args, ebph_func='reset_profile')
    #def reset(res=None):
    #    pass

    # Handle command
    commands[args.command]()
