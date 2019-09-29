# ebpH --  An eBPF intrusion detection program.
# -------  Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebphd <COMMAND>
#
# Licensed under GPL v2 License

import os, sys, socket, signal, time, logging, re
from threading import Thread
from collections import defaultdict
import ctypes as ct

from bcc import BPF, lib

from daemon import Daemon
from config import Config
import utils
import structs

BPF_C = utils.path('src/c/bpf.c')

def load_bpf_program(path):
    with open(path, 'r') as f:
        text = f.read()
        for match in re.findall(r"(#include\s*\"(.*)\")", text):
            real_header_path = os.path.abspath(utils.path(match[1]))
            text = text.replace(match[0], ''.join(['#include "', real_header_path, '"']))
    return BPF(text=text)

class ebpHD(Daemon):
    def __init__(self, monitoring=True):
        super().__init__(Config.pidfile, Config.socket)

        self.monitoring = monitoring

        self.bpf = None

        # bpf stats
        self.num_profiles = 0
        self.num_syscalls = 0
        self.num_forks    = 0
        self.num_execves  = 0
        self.num_exits    = 0

        # number of elapsed ticks since creation
        self.ticks = 0

        self.logger = logging.getLogger('ebpH')

    def main(self):
        self.logger.info("Starting ebpH daemon...")

        # register handlers
        signal.signal(signal.SIGTERM, self.on_term)
        signal.signal(signal.SIGINT, self.on_term)

        if self.monitoring:
            self.start_monitoring()
        while True:
            if self.monitoring:
                self.tick()
            time.sleep(Config.ticksleep)

    def stop(self):
        self.logger.info("Stopping ebpH daemon...")
        super().stop()

    # BPF stuff below this line --------------------

    def register_perf_buffers(self, bpf):
        # executable has been processed in ebpH_on_do_open_execat
        def on_pid_assoc(cpu, data, size):
            event = bpf["on_pid_assoc"].event(data)
            s = f"PID {event.pid} associated with profile {event.comm.decode('utf-8')} ({event.key})"
            self.logger.debug(s)
        bpf["on_pid_assoc"].open_perf_buffer(on_pid_assoc)

        # executable has been processed in ebpH_on_do_open_execat
        def on_executable_processed(cpu, data, size):
            event = bpf["on_executable_processed"].event(data)
            s = f"Constructed ebpH profile for {event.comm.decode('utf-8')} ({event.key})"
            self.logger.info(s)
        bpf["on_executable_processed"].open_perf_buffer(on_executable_processed)

        # Anomaly detected
        def on_anomaly(cpu, data, size):
            event = bpf["on_anomaly"].event(data)
            s = f"PID {event.pid} ({event.comm.decode('utf-8')} {event.key}): {event.anomalies} detected for syscall {event.syscall} "
            self.logger.warning(s)
        bpf["on_anomaly"].open_perf_buffer(on_anomaly)

        # error, warning, debug, info
        def on_error(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.error(s)
        bpf["ebpH_error"].open_perf_buffer(on_error)

        def on_warning(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.warning(s)
        bpf["ebpH_warning"].open_perf_buffer(on_warning)

        def on_debug(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.debug(s)
        bpf["ebpH_debug"].open_perf_buffer(on_debug)

        def on_info(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.info(s)
        bpf["ebpH_info"].open_perf_buffer(on_info)

        self.logger.debug(f'Registered perf buffers successfully for {bpf}')

    def start_monitoring(self):
        self.monitoring = True

        # compile ebpf code
        self.bpf = load_bpf_program(BPF_C)
        self.register_perf_buffers(self.bpf)

        self.load_profiles()
        self.bpf.attach_kretprobe(event='do_open_execat', fn_name='ebpH_on_do_open_execat')
        self.logger.info('Started monitoring the system')

    def on_term(self, sn=None, frame=None):
        if self.monitoring:
            self.stop_monitoring()
        sys.exit(0)

    def stop_monitoring(self):
        self.save_profiles()
        self.bpf.cleanup()
        self.bpf = None
        self.monitoring = False

        self.logger.warning('Stopped monitoring the system')

    # save all profiles to disk
    def save_profiles(self):
        for profile in self.bpf["profiles"].values():
            path = os.path.join(Config.profiles_dir, str(profile.key))
            # make sure that the files are only readable and writable by root
            with open(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600), 'wb') as f:
                f.write(profile)
            # just in case the file already existed with the wrong permissions
            os.chmod(path, 0o600)
            self.logger.info(f"Successfully saved profile {profile.comm.decode('utf-8')} ({profile.key})")

    # load all profiles from disk
    def load_profiles(self):
        for filename in os.listdir(Config.profiles_dir):
            # Read bytes from profile file
            path = os.path.join(Config.profiles_dir, filename)
            with open(path, 'rb') as f:
                profile = f.read()

            # Yoink structure info from the init array
            # FIXME: This is kind of hacky, but it works
            profile_struct = self.bpf["__executable_init"][0]
            # Make sure we're not messing with memory we shouldn't
            fit = min(len(profile), ct.sizeof(profile_struct))
            # Write contents of profile into profile_struct
            ct.memmove(ct.addressof(profile_struct), profile, fit)
            # Update our profile map
            self.bpf["profiles"].__setitem__(ct.c_int64(profile_struct.key), profile_struct)

            self.logger.info(f"Successfully loaded profile {profile_struct.comm.decode('utf-8')} ({profile_struct.key})")

    def tick(self):
        self.ticks = self.ticks + 1

        # socket stuff below this line ----------------------
        #connection, client_address = self._socket.accept()

        # bpf stuff below this line -------------------------
        if self.monitoring:
            self.bpf.perf_buffer_poll(30)
            #self.num_profiles = self.bpf["profiles"].values()[0].value
            #self.num_syscalls = self.bpf["syscalls"].values()[0].value
            #self.num_forks    = self.bpf["forks"].values()[0].value
            #self.num_execves  = self.bpf["execves"].values()[0].value
            #self.num_exits    = self.bpf["exits"].values()[0].value

