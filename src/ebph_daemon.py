import os, sys
import atexit
import socket
import signal
import time
import threading
import logging
import logging.handlers

from daemon import Daemon
from bpf_program import BPFProgram
from server import EBPHUnixStreamServer, EBPHRequestDispatcher
from utils import locks, to_json_bytes, from_json_bytes
import config

class EBPHDaemon(Daemon):
    monitoring_lock = threading.Lock()
    profiles_lock = threading.Lock()
    processes_lock = threading.Lock()

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
        self.request_dispatcher.register(self.reset_profile)

    # Listen for incoming socket connections and dispatch to connection handler thread
    def listen_for_connections(self):
        self.logger.info("Starting ebpH server...")
        self.server = EBPHUnixStreamServer(self.request_dispatcher)
        self.logger.info(f"Server listening for connections on {self.server.server_address}")
        self.server.serve_forever()

    def tick(self):
        self.tick_count += 1

        if self.tick_count % config.saveinterval == 0:
            self.save_profiles()

        self.bpf_program.on_tick()

    def main(self):
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
        self.logger.info("Stopping ebpH daemon...")
        super().stop()

    # Commands below this line -----------------------------------
    # Return values must be json parsable

    @locks(monitoring_lock)
    def start_monitoring(self):
        return self.bpf_program.start_monitoring()

    @locks(monitoring_lock)
    def stop_monitoring(self):
        return self.bpf_program.stop_monitoring()

    @locks(monitoring_lock)
    def is_monitoring(self):
        return self.bpf_program.monitoring

    @locks(monitoring_lock)
    def status(self):
        status = {
                'Monitoring': self.bpf_program.monitoring,
                'Profiles': self.bpf_program.profile_count,
                'TasksMonitored': self.bpf_program.process_count,
                }
        return status

    @locks(profiles_lock)
    def save_profiles(self):
        return self.bpf_program.save_profiles()

    @locks(profiles_lock)
    def fetch_profile(self, key):
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

    @locks(processes_lock)
    def fetch_process(self, key):
        process = self.bpf_program.fetch_process(key)
        attrs = {'pid': process.pid,
                'tid': process.tid,
                'profile': self.fetch_profile(process.exe_key),
                }
        return attrs

    def fetch_profiles(self):
        profiles = {}
        for k, v in self.bpf_program.bpf["profiles"].iteritems():
            k = k.value
            profiles[k] = self.fetch_profile(k)
        return profiles

    def fetch_processes(self):
        processes = {}
        for k, v in self.bpf_program.bpf["processes"].iteritems():
            k = k.value
            try:
                processes[k] = self.fetch_process(k)
            except KeyError:
                pass
        return processes

    def reset_profile(self, key):
        return self.bpf_program.reset_profile(key)

