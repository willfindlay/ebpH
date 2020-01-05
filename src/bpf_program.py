# ebpH  An eBPF intrusion detection program. Monitors system call patterns and detect anomalies.
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

import os, sys
import logging
import atexit
import ctypes as ct
import signal
import threading

from bcc import BPF, lib

import config

# register handlers
signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

class BPFProgram:
    def __init__(self, should_save, should_load):
        # Should we save/load profiles?
        self.should_load = should_load
        self.should_save = should_save

        # BPF program
        self.bpf = None

        # Logging stuff
        self.logger = logging.getLogger('ebpH')

    def cleanup(self):
        self.logger.info('Unloading BPF program...')
        try:
            self.stop_monitoring()
        except TypeError:
            pass
        self.logger.info('BPF program unloaded')

    def register_exit_hooks(self):
        atexit.unregister(self.cleanup)
        atexit.register(self.cleanup)
        self.logger.info("Registered BPFProgram exit hooks")

    def register_perf_buffers(self):
        # Returns a lost callback for a perf buffer with name buff_name
        def lost_cb(buff_name):
            def closure(lost):
                self.logger.warning(f"Lost {lost} samples from perf_buffer {buff_name}")
            return closure

        # executable has been processed in ebpH_on_do_open_execat
        def on_pid_assoc(cpu, data, size):
            event = self.bpf["on_pid_assoc"].event(data)
            s = f"PID {event.pid} associated with profile {event.comm.decode('utf-8')} ({event.key})"
            self.logger.debug(s)
        self.bpf["on_pid_assoc"].open_perf_buffer(on_pid_assoc, lost_cb=lost_cb("on_pid_assoc"))

        # executable has been processed in ebpH_on_do_open_execat
        def on_executable_processed(cpu, data, size):
            event = self.bpf["on_executable_processed"].event(data)
            s = f"Constructed profile for {event.comm.decode('utf-8')} ({event.key})"
            self.logger.info(s)
        self.bpf["on_executable_processed"].open_perf_buffer(on_executable_processed, lost_cb=lost_cb("on_executable_processed"))

        # Anomaly detected
        def on_anomaly(cpu, data, size):
            event = self.bpf["on_anomaly"].event(data)
            s = f"PID {event.pid} ({event.comm.decode('utf-8')} {event.key}): {event.anomalies} anomalies detected for syscall {event.syscall} "
            self.logger.warning(s)
        self.bpf["on_anomaly"].open_perf_buffer(on_anomaly, lost_cb=lost_cb("on_anomaly"))

        # error, warning, debug, info
        def on_error(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.error(s)
        self.bpf["ebpH_error"].open_perf_buffer(on_error, lost_cb=lost_cb("on_error"))

        def on_warning(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.warning(s)
        self.bpf["ebpH_warning"].open_perf_buffer(on_warning, lost_cb=lost_cb("on_warning"))

        def on_debug(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.debug(s)
        self.bpf["ebpH_debug"].open_perf_buffer(on_debug, lost_cb=lost_cb("on_debug"))

        def on_debug_int(cpu, data, size):
            event = ct.cast(data, ct.POINTER(ct.c_ulong)).contents.value
            s = f"{event}"
            self.logger.debug(s)
        self.bpf["ebpH_debug_int"].open_perf_buffer(on_debug_int, lost_cb=lost_cb("on_debug_int"))

        def on_info(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.info(s)
        self.bpf["ebpH_info"].open_perf_buffer(on_info, lost_cb=lost_cb("on_info"))

        self.logger.info(f'Registered perf buffers')

    def load_bpf(self):
        assert self.bpf == None
        self.logger.info('Initializing BPF program...')

        # Set flags
        flags = []
        # Include project src
        flags.append(f"-I{config.project_path}/src")

        # Compile ebpf code
        with open(config.bpf_program, "r") as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=flags)

        # Regiter exit hooks and perf buffers
        self.register_exit_hooks()
        self.register_perf_buffers()

        if self.should_load:
            self.load_profiles()
            self.logger.info('Loaded profiles')

        self.start_monitoring()

        self.logger.info('BPF program initialized')

    # Poll perf_buffers on every daemon tick
    def on_tick(self):
        self.bpf.perf_buffer_poll(30)

# Commands below this line ----------------------------------------------

    def start_monitoring(self):
        """
        Start monitoring the system.
        Return 0 on success, 1 if system is already being monitored.
        """
        if self.monitoring:
            self.logger.info('System is already being monitored')
            return 1
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), ct.c_int(1))
        self.logger.info('Started monitoring the system')
        return 0

    def stop_monitoring(self):
        """
        Stop monitoring the system.
        Return 0 on success, 1 if system is already not being monitored.
        """
        if not self.monitoring:
            self.logger.info('System is not being monitored')
            return 1
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), ct.c_int(0))
        if self.should_save:
            self.save_profiles()
        self.logger.info('Stopped monitoring the system')
        return 0

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
            path = os.path.join(config.profiles_dir, str(profile.key))
            # Make sure that the files are only readable and writable by root
            with open(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600), 'wb') as f:
                f.write(profile)
            # Just in case the file already existed with the wrong permissions
            os.chmod(path, 0o600)
            self.logger.debug(f"Successfully saved profile {profile.comm.decode('utf-8')} ({profile.key})")
        self.logger.info(f"Successfully saved all profiles")

        # return to original state
        self.bpf["__is_saving"].__setitem__(ct.c_int(0), ct.c_int(0))
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), monitoring)

    # load all profiles from disk
    def load_profiles(self):
        for filename in os.listdir(config.profiles_dir):
            # Read bytes from profile file
            path = os.path.join(config.profiles_dir, filename)
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

    def fetch_profile(self, key):
        # TODO: check if bpf is None
        return self.bpf['profiles'][ct.c_uint64(key)]

    def fetch_process(self, key):
        # TODO: check if bpf is None
        return self.bpf['processes'][ct.c_uint64(key)]

# Attribute stuff below this line --------------------------------------------------------

    def __getattribute__(self, attr):
        if attr == 'profile_count':
            try:
                return len(self.bpf["profiles"].values())
            except TypeError:
                return 0
        elif attr == 'process_count':
            try:
                return len(self.bpf["processes"].values())
            except TypeError:
                return 0
        elif attr == 'monitoring':
            try:
                return bool(self.bpf["__is_monitoring"][0].value)
            except TypeError:
                return False
        return super().__getattribute__(attr)
