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
    sudo ebph-admin
"""

def command(operation, *command_arguments, ebph_func=None):
    """
    Decorator for commands sent to ebphd.
    Handles all socket-related operations.
    Decorated functions should be of the form func(res) where res is the resonse from the server.
    """
    if not ebph_func:
        ebph_func = operation
    def decorator(func):
        def inner():
            try:
                # Connect to socket
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(config.socket)
                # Form request
                request = {'func': ebph_func, 'args': command_arguments}
                # Send request
                send_message(sock, to_json_bytes(request))
                # Handle response
                res = receive_message(sock)
                res = from_json_bytes(res)
                return func(res)
            except ConnectionRefusedError:
                print(f"Unable to connect to {config.socket}... Is ebphd running?", file=sys.stderr)
            finally:
                sock.close()
        return inner
    return decorator

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, prog="ebph-admin", epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    commands = parser.add_subparsers(title="possible commands", dest="command", required=1, metavar='command')
    pause = commands.add_parser('pause',
            help="Pause system monitoring without killing the daemon.")

    resume = commands.add_parser('resume',
            help="Resume system monitoring.")

    #start = commands.add_parser('start',
    #        help="Start the ebpH daemon.")

    #restart = commands.add_parser('restart',
    #        help="Restart the ebpH daemon.")

    #stop = commands.add_parser('stop',
    #        help="Stop the ebpH daemon.")

    is_monitoring = commands.add_parser('is-monitoring',
            help="Check if the daemon is monitoring the system.")

    #reset_profile = commands.add_parser('reset-profile',
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

    @command('resume', ebph_func='start_monitoring')
    def resume(res=None):
        if res['code'] != 200:
            print(f"Could not complete command. System replied with code: {res['code']}.")
            sys.exit(-1)
        elif res['message']:
            print(f"System is already being monitored.")
        else:
            print(f"System monitoring resumed.")

    @command('pause', ebph_func='stop_monitoring')
    def pause(res=None):
        if res['code'] != 200:
            print(f"Could not complete command. System replied with code: {res['code']}.")
            sys.exit(-1)
        elif res['message']:
            print(f"System is not being monitored.")
        else:
            print(f"System monitoring paused.")

    @command('is_monitoring', ebph_func='is_monitoring')
    def is_monitoring(res=None):
        if res['code'] != 200:
            print(f"Could not complete command. System replied with code: {res['code']}.")
            sys.exit(-1)
        if res['message']:
            print(f"Yes")
        else:
            print(f"No")

    # Handle command
    if  args.command == 'resume':
        resume()
    if  args.command == 'pause':
        pause()
    if  args.command == 'is-monitoring':
        is_monitoring()
