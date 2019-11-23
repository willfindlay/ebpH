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

import os, sys, socket, signal, time, logging, re, atexit
from collections import defaultdict
import ctypes as ct

from bcc import BPF, lib

from daemon import Daemon
from config import Config
import utils
import structs


# register handlers
signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

BPF_C = utils.path('src/ebphd/bpf/bpf.c')

def load_bpf_program(path):
    with open(path, 'r') as f:
        text = f.read()
        for match in re.findall(r"(#include\s*\"(.*)\")", text):
            real_header_path = os.path.abspath(utils.path(match[1]))
            text = text.replace(match[0], ''.join(['#include "', real_header_path, '"']))
    return BPF(text=text)

class Ebphd(Daemon):
    def __init__(self, args):
        super().__init__(Config.pidfile, Config.socket)

        self.should_load = not args.noload
        self.should_save = not args.nosave

        self.bpf = None

        # bpf stats
        self.num_profiles = 0
        self.num_syscalls = 0
        self.num_forks    = 0
        self.num_execves  = 0
        self.num_exits    = 0

        # number of elapsed ticks since creation
        self.tick_count = 0

        self.logger = logging.getLogger('ebpH')

    def main(self):
        self.logger.info("Starting ebpH daemon...")

        self.load_bpf()
        while True:
            self.tick()
            time.sleep(Config.ticksleep)

    def stop(self):
        self.logger.info("Stopping ebpH daemon...")
        super().stop()

    def socket_loop(self):
        while True:
            connection, client_addr = self._socket.accept()
            client_thread = threading.Thread(target=self.on_new_client, args=(connection, client_addr))
            client_thread.daemon = True
            client_thread.start()

    def on_new_client(self, connection, client_addr):
            try:
                self.logger.debug(f"Connection from {client_addr}")
                while True:
                    data = connection.recv(1024)
                    if data:
                        pass
                    else:
                        break
            finally:
                connection.close()
                self.logger.debug(f"Connection to {client_addr} closed")

    # BPF stuff below this line --------------------

    def register_perf_buffers(self, bpf):
        # Returns a lost callback for a perf buffer with name buff_name
        def lost_cb(buff_name):
            def closure(lost):
                self.logger.warning(f"Lost {lost} samples from perf_buffer {buff_name}")
            return closure

        # executable has been processed in ebpH_on_do_open_execat
        def on_pid_assoc(cpu, data, size):
            event = bpf["on_pid_assoc"].event(data)
            s = f"PID {event.pid} associated with profile {event.comm.decode('utf-8')} ({event.key})"
            # FIXME: commented out because this is annoying
            #self.logger.debug(s)
        bpf["on_pid_assoc"].open_perf_buffer(on_pid_assoc, lost_cb=lost_cb("on_pid_assoc"))

        # executable has been processed in ebpH_on_do_open_execat
        def on_executable_processed(cpu, data, size):
            event = bpf["on_executable_processed"].event(data)
            s = f"Constructed profile for {event.comm.decode('utf-8')} ({event.key})"
            self.logger.info(s)
        bpf["on_executable_processed"].open_perf_buffer(on_executable_processed, lost_cb=lost_cb("on_executable_processed"))

        # Anomaly detected
        def on_anomaly(cpu, data, size):
            event = bpf["on_anomaly"].event(data)
            s = f"PID {event.pid} ({event.comm.decode('utf-8')} {event.key}): {event.anomalies} anomalies detected for syscall {event.syscall} "
            self.logger.warning(s)
        bpf["on_anomaly"].open_perf_buffer(on_anomaly, lost_cb=lost_cb("on_anomaly"))

        # error, warning, debug, info
        def on_error(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.error(s)
        bpf["ebpH_error"].open_perf_buffer(on_error, lost_cb=lost_cb("on_error"))

        def on_warning(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.warning(s)
        bpf["ebpH_warning"].open_perf_buffer(on_warning, lost_cb=lost_cb("on_warning"))

        def on_debug(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.debug(s)
        bpf["ebpH_debug"].open_perf_buffer(on_debug, lost_cb=lost_cb("on_debug"))

        def on_debug_int(cpu, data, size):
            event = ct.cast(data, ct.POINTER(ct.c_ulong)).contents.value
            s = f"{event}"
            self.logger.debug(s)
        bpf["ebpH_debug_int"].open_perf_buffer(on_debug_int, lost_cb=lost_cb("on_debug_int"))

        def on_info(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.info(s)
        bpf["ebpH_info"].open_perf_buffer(on_info, lost_cb=lost_cb("on_info"))

        self.logger.info(f'Registered perf buffers')

    def load_bpf(self, should_start=True):
        # compile ebpf code
        self.logger.info('Initializing BPF program...')
        self.bpf = load_bpf_program(BPF_C)
        atexit.register(self.cleanup)
        if should_start:
            self.start_monitoring()
        self.register_perf_buffers(self.bpf)

        self.bpf.attach_kretprobe(event='do_open_execat', fn_name='ebpH_on_do_open_execat')
        self.logger.info('Attached execve hook')
        self.bpf.attach_kretprobe(event='complete_signal', fn_name='ebpH_on_complete_signal')
        self.logger.info('Attached signal hook')

        if self.should_load:
            self.load_profiles()
            self.logger.info('Loaded profiles')
        self.logger.info('BPF program initialized')

    def cleanup(self):
        try:
            self.stop_monitoring()
        except TypeError:
            pass
        self.logger.info('BPF program unloaded')

    def start_monitoring(self):
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), ct.c_int(1))
        self.logger.info('Started monitoring the system')

    def stop_monitoring(self):
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), ct.c_int(0))
        if self.should_save:
            self.save_profiles()
        self.logger.info('Stopped monitoring the system')

    # save all profiles to disk
    def save_profiles(self):
        # notify bpf that we are saving
        self.bpf["__is_saving"].__setitem__(ct.c_int(0), ct.c_int(1))
        # save monitoring state to be restored later
        monitoring = self.bpf["__is_monitoring"][0]
        # wait until bpf stops monitoring
        while(self.bpf["__is_monitoring"][0]):
            pass
        # Must be itervalues, not values
        for profile in self.bpf["profiles"].itervalues():
            print(profile)
            path = os.path.join(Config.profiles_dir, str(profile.key))
            # Make sure that the files are only readable and writable by root
            with open(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600), 'wb') as f:
                f.write(profile)
            # Just in case the file already existed with the wrong permissions
            os.chmod(path, 0o600)
            self.logger.info(f"Successfully saved profile {profile.comm.decode('utf-8')} ({profile.key})")

        # return to original state
        self.bpf["__is_saving"].__setitem__(ct.c_int(0), ct.c_int(0))
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), monitoring)

    # load all profiles from disk
    def load_profiles(self):
        for filename in os.listdir(Config.profiles_dir):
            # Read bytes from profile file
            path = os.path.join(Config.profiles_dir, filename)
            with open(path, 'rb') as f:
                profile = f.read()

            # Yoink structure info from the init array
            # FIXME: This is kind of hacky, but it works
            profile_struct = self.bpf["__profile_init"][0]
            # Make sure we're not messing with memory we shouldn't
            fit = min(len(profile), ct.sizeof(profile_struct))
            # Write contents of profile into profile_struct
            ct.memmove(ct.addressof(profile_struct), profile, fit)
            # Update our profile map
            self.bpf["profiles"].__setitem__(ct.c_int64(profile_struct.key), profile_struct)

            self.logger.info(f"Successfully loaded profile {profile_struct.comm.decode('utf-8')} ({profile_struct.key})")

    def profile_count(self):
        try:
            return len(self.bpf["profiles"].values())
        except TypeError:
            return 0

    def process_count(self):
        try:
            return len(self.bpf["processes"].values())
        except TypeError:
            return 0

    def is_monitoring(self):
        try:
            return bool(self.bpf["__is_monitoring"][0].value)
        except TypeError:
            return False

    def tick(self):
        self.tick_count += 1

        if self.tick_count % Config.saveinterval == 0:
            self.save_profiles()

        # bpf stuff below this line -------------------------
        if self.bpf:
            self.bpf.perf_buffer_poll(30)
