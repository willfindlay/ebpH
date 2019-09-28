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

def create_bpf_factory(path):
    def closure():
        return load_bpf_program(path)
    return closure

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
            s = f"PID {event.pid} associated with {event.comm.decode('utf-8')} ({event.key})."
            self.logger.debug(s)
        bpf["on_pid_assoc"].open_perf_buffer(on_pid_assoc)

        # executable has been processed in ebpH_on_do_open_execat
        def on_executable_processed(cpu, data, size):
            event = bpf["on_executable_processed"].event(data)
            s = f"Registered executable {event.comm.decode('utf-8')} ({event.key})."
            self.logger.info(s)
        bpf["on_executable_processed"].open_perf_buffer(on_executable_processed)

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

        self.logger.debug(f'Registered perf buffers successfully for {bpf}.')

    def start_monitoring(self):
        self.monitoring = True

        # compile ebpf code
        self.bpf = load_bpf_program(BPF_C)
        self.register_perf_buffers(self.bpf)

        #self.logger.info("Loaded profiles successfully.")
        #loaded = sorted([''.join([v.comm.decode('utf-8'), ' (', str(v.key), ')']) for v in self.bpf['profile'].values()], key=lambda x: x.upper())
        #self.logger.info('\n\t\t\t'.join(['The following profiles have been loaded:'] + loaded))

        # register callback to load profiles
        # FIXME: might fundamentally change how this works, so leaving it commented for now
        #self.bpf.attach_uretprobe(name=defs.LOADER_PATH, sym='load_profile', fn_name='pH_load_profile')

        #execve_fnname = self.bpf.get_syscall_fnname("execve")
        #self.bpf.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        self.bpf.attach_kretprobe(event='do_open_execat', fn_name='ebpH_on_do_open_execat')

        self.logger.info('Started monitoring the system.')

    def on_term(self, sn=None, frame=None):
        if self.monitoring:
            # TODO: remove, just for testing
            for v in self.bpf["executables"].values():
                self.logger.info(v.comm)
            self.stop_monitoring()
        sys.exit(0)

    def stop_monitoring(self):
        self.save_profiles()
        self.bpf.cleanup()
        self.bpf = None
        self.monitoring = False

        self.logger.warning('Stopped monitoring the system.')

    # save all profiles to disk
    def save_profiles(self):
        pass

    # load all profiles from disk
    def load_profiles(self):
        pass

    def pin_map(self, name, dir=Config.ebphfs):
        fn = os.path.join(dir, name)
        # remove filename before trying to pin
        if os.path.exists(fn):
            os.unlink(fn)

        # pin the map
        ret = lib.bpf_obj_pin(self.bpf[f"{name}"].map_fd, f"{fn}".encode('utf-8'))
        if ret:
            self.logger.error(f"Unable to pin map {fn}: {os.strerror(ct.get_errno())}")

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

