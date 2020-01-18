import os, sys
import atexit
import socket
import signal
import time
import threading
import logging
import logging.handlers
import struct

from daemon import Daemon
from bpf_program import BPFProgram
from server import EBPHUnixStreamServer, EBPHRequestDispatcher
from utils import locks, to_json_bytes, from_json_bytes
import config

class EBPHDaemon(Daemon):
    """
    EBPHDaemon

    This class provides the logic for the daemon and exposes methods for interacting with the
    underlying BPFProgram class.

    Right now, the relationship bewteen the Daemon and BPFProgram is "has-a", but in the
    future this might become inheritance. Not sure what the best approach is here.
    """
    def __init__(self, args):
        # Init Daemon superclass
        super().__init__(config.pidfile, config.socket)

        # BPF Program
        self.bpf_program = BPFProgram(args)

        # Set args
        self.args = args

        # Number of elapsed ticks
        self.tick_count = 0

        # Logging stuff
        self.logger = logging.getLogger('ebpH')

        # Request dispatcher for server
        self.request_dispatcher = EBPHRequestDispatcher(self)
        # TODO: register commands with dispatcher here
        self.request_dispatcher.register(self.start_monitoring)
        self.request_dispatcher.register(self.stop_monitoring)
        self.request_dispatcher.register(self.is_monitoring)
        self.request_dispatcher.register(self.status)
        self.request_dispatcher.register(self.save_profiles)
        self.request_dispatcher.register(self.fetch_profile)
        self.request_dispatcher.register(self.fetch_profiles)
        self.request_dispatcher.register(self.fetch_process)
        self.request_dispatcher.register(self.fetch_processes)
        #self.request_dispatcher.register(self.reset_profile)
        #self.request_dispatcher.register(self.inspect_profile)

    # Listen for incoming socket connections and dispatch to connection handler thread
    def listen_for_connections(self):
        """
        Called by the connection handler thread to listen for incoming socket connections.
        """
        self.logger.info("Starting ebpH server...")
        self.server = EBPHUnixStreamServer(self.request_dispatcher)
        self.logger.info(f"Server listening for connections on {self.server.server_address}")
        self.server.serve_forever()

    def tick(self):
        """
        Invoked on every tick in the main event loop.
        """
        self.tick_count += 1

        if self.tick_count % config.saveinterval == 0:
            self.save_profiles()

        self.bpf_program.on_tick()

    def main(self):
        """
        Main daemon setup + event loop.
        """
        self.logger.info("Starting ebpH daemon...")
        self.bpf_program.load_bpf()

        # Spawn connection listener here
        self.connection_listener = threading.Thread(target=self.listen_for_connections)
        self.connection_listener.daemon = True
        self.connection_listener.start()

        # Event loop
        while True:
            self.tick()
            time.sleep(config.ticksleep)

    def stop(self):
        """
        Stop the daemon. Overloaded from base daemon class to print log info.
        """
        self.logger.info("Stopping ebpH daemon...")
        super().stop()

    # Commands below this line -----------------------------------
    # Return values must be json parsable

    def start_monitoring(self):
        """
        Start monitoring the system.
        """
        return self.bpf_program.start_monitoring()

    def stop_monitoring(self):
        """
        Stop monitoring the system.
        """
        return self.bpf_program.stop_monitoring()

    def is_monitoring(self):
        """
        Return true if we are monitoring, else false.
        """
        return self.bpf_program.monitoring

    def status(self):
        """
        Return a dictionary of basic information about ebphd's state.
        """
        status = {
                'Monitoring': self.bpf_program.monitoring,
                'Profiles': self.bpf_program.profile_count,
                'TasksMonitored': self.bpf_program.process_count,
                'SyscallsCount': self.bpf_program.syscall_count,
                }
        return status

    def save_profiles(self):
        """
        Save all profiles to disk.
        """
        return self.bpf_program.save_profiles()

    def fetch_profile(self, key):
        """
        Return a dictionary of basic profile info excluding things like lookahead pairs.
        """
        profile = self.bpf_program.fetch_profile(key)
        attrs = {'comm': profile.comm.decode('utf-8'),
                'key': profile.key,
                'frozen': profile.frozen,
                'normal': profile.normal,
                'normal_time': profile.normal_time,
                'normal_count': profile.train.normal_count,
                'last_mod_count': profile.train.last_mod_count,
                'train_count': profile.train.train_count,
                'anomalies': profile.anomalies,
                }
        return attrs

    #def inspect_profile(self, key):
    #    """
    #    Return a dictionary of ALL profile info, including things like lookahead pairs.
    #    """
    #    key = int(key)
    #    profile = self.bpf_program.fetch_profile(key)
    #    data = profile.test if profile.normal else profile.train
    #    lookahead_pairs = list(data.flags)
    #    print(lookahead_pairs)
    #    attrs = {'comm': profile.comm.decode('utf-8'),
    #            'key': profile.key,
    #            'frozen': profile.frozen,
    #            'normal': profile.normal,
    #            'normal_time': profile.normal_time,
    #            'normal_count': profile.train.normal_count,
    #            'last_mod_count': profile.train.last_mod_count,
    #            'train_count': profile.train.train_count,
    #            'anomalies': profile.anomalies,
    #            'lookahead_pairs': lookahead_pairs
    #            }
    #    return attrs

    def fetch_process(self, key):
        """
        Return a dictionary of basic process info, including the accompanying profile.
        """
        process = self.bpf_program.fetch_process(key)
        attrs = {'pid': process.pid,
                'tid': process.tid,
                'profile': self.fetch_profile(process.exe_key),
                }
        return attrs

    def fetch_profiles(self):
        """
        Return profile info for all profiles.
        """
        profiles = {}
        for k, v in self.bpf_program.bpf["profiles"].iteritems():
            k = k.value
            profiles[k] = self.fetch_profile(k)
        return profiles

    def fetch_processes(self):
        """
        Return process info for all processes.
        """
        processes = {}
        for k, v in self.bpf_program.bpf["processes"].iteritems():
            k = k.value
            try:
                processes[k] = self.fetch_process(k)
            except KeyError:
                pass
        return processes

    #def reset_profile(self, key):
    #    """
    #    Reset a profile. WARNING: not yet working 100%
    #    """
    #    return self.bpf_program.reset_profile(key)

