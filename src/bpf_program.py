# ebpH An eBPF intrusion detection program.
#      Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# Licensed under GPL v2 License

import os, sys
import logging
import atexit
import ctypes as ct
import signal
import threading
import time
import subprocess

from bcc import BPF, lib

from structs import EBPHProfile
from utils import locks
import config

logger = logging.getLogger('ebpH')

# register handlers
def handle_sigterm(x, y):
    logger.warning("Caught SIGTERM")
    sys.exit(0)
signal.signal(signal.SIGTERM, handle_sigterm)
def handle_sigint(x, y):
    logger.warning("Caught SIGINT")
    sys.exit(0)
signal.signal(signal.SIGINT, handle_sigint)

class BPFProgram:
    monitoring_lock = threading.Lock()
    profiles_lock = threading.Lock()
    processes_lock = threading.Lock()

    def __init__(self, args):
        self.args = args

        # BPF program
        self.bpf = None

    def cleanup(self):
        logger.info('Running cleanup hooks...')
        self.stop_monitoring()
        self.save_profiles()
        logger.info('BPF program unloaded')

    def register_exit_hooks(self):
        atexit.unregister(self.cleanup)
        atexit.register(self.cleanup)
        logger.info("Registered BPFProgram exit hooks")

    def register_perf_buffers(self):
        # Returns a lost callback for a perf buffer with name buff_name
        def lost_cb(buff_name):
            def closure(lost):
                logger.warning(f"Lost {lost} samples from perf_buffer {buff_name}")
            return closure

        # executable has been processed in ebpH_on_do_open_execat
        def on_executable_processed(cpu, data, size):
            event = self.bpf["on_executable_processed"].event(data)
            s = f"Constructed profile for {event.comm.decode('utf-8')} ({event.key})"
            logger.info(s)
        self.bpf["on_executable_processed"].open_perf_buffer(on_executable_processed, lost_cb=lost_cb("on_executable_processed"))

        # Anomaly detected
        def on_anomaly(cpu, data, size):
            event = self.bpf["on_anomaly"].event(data)
            s = f"PID {event.pid} ({event.comm.decode('utf-8')} {event.key}): {event.anomalies} anomalies detected for syscall {event.syscall} "
            logger.warning(s)
        self.bpf["on_anomaly"].open_perf_buffer(on_anomaly, lost_cb=lost_cb("on_anomaly"))

        # error, warning
        def on_error(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            logger.error(s)
        self.bpf["ebpH_error"].open_perf_buffer(on_error, lost_cb=lost_cb("on_error"))

        def on_warning(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            logger.warning(s)
        self.bpf["ebpH_warning"].open_perf_buffer(on_warning, lost_cb=lost_cb("on_warning"))

        logger.info(f'Registered perf buffers')

    def load_bpf(self):
        assert self.bpf == None
        logger.info('Initializing BPF program...')

        # Set flags
        flags = []
        if self.args.debug:
            flags.append("-DEBPH_DEBUG")
        if self.args.ludikris:
            flags.append("-DLUDIKRIS")
        for k, v in config.bpf_params.items():
            if type(v) == str:
                v = f"\"{v}\""
            logger.info(f"Using {k}={v}...")
            flags.append(f"-D{k}={v}")
        # Include project src
        flags.append(f"-I{config.project_path}/src")
        # Estimate epoch boot time.
        # This is used to establish normal times within the BPF program
        # since eBPF only provides times since system boot.
        boot_time = time.monotonic() * 1000000000
        boot_epoch = time.time() * 1000000000 - boot_time
        flags.append(f"-DEBPH_BOOT_EPOCH=(u64){boot_epoch}")

        # Compile and load eBPF program
        with open(config.bpf_program, "r") as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=flags)

        # Regiter exit hooks and perf buffers
        self.register_exit_hooks()
        self.register_perf_buffers()

        self.load_profiles()
        self.start_monitoring()

        logger.info('BPF program initialized')

    def trace_print(self):
        while True:
            fields = self.bpf.trace_fields(nonblocking=True)
            msg = fields[-1]
            if msg == None:
                return
            logger.debug(msg.decode('utf-8'))

    # Poll perf_buffers on every daemon tick
    def on_tick(self):
        self.bpf.perf_buffer_poll(30)
        if self.args.debug:
            self.trace_print()

# Commands below this line ----------------------------------------------

    @locks(monitoring_lock)
    def start_monitoring(self):
        """
        Start monitoring the system.
        Return 0 on success, 1 if system is already being monitored.
        """
        if self.monitoring:
            logger.info('System is already being monitored')
            return 1
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), ct.c_int(1))
        logger.info('Started monitoring the system')
        return 0

    @locks(monitoring_lock)
    def stop_monitoring(self):
        """
        Stop monitoring the system.
        Return 0 on success, 1 if system is already not being monitored.
        """
        if not self.monitoring:
            logger.info('System is not being monitored')
            return 1
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), ct.c_int(0))
        logger.info('Stopped monitoring the system')
        return 0

    # save all profiles to disk
    @locks(profiles_lock)
    def save_profiles(self):
        if self.args.nosave:
            logger.warning("nosave flag is set, refusing to save profiles!")
            return
        # save monitoring state to be restored later
        monitoring = self.bpf["__is_monitoring"][0]
        # notify bpf that we are saving
        self.bpf["__is_saving"].__setitem__(ct.c_int(0), ct.c_int(1))
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
            logger.debug(f"Successfully saved profile {profile.comm.decode('utf-8')} ({profile.key})")
        logger.info(f"Successfully saved all profiles")

        # return to original state
        self.bpf["__is_saving"].__setitem__(ct.c_int(0), ct.c_int(0))
        self.bpf["__is_monitoring"].__setitem__(ct.c_int(0), monitoring)

    # load all profiles from disk
    @locks(profiles_lock)
    def load_profiles(self):
        if self.args.noload:
            logger.warning("noload flag is set, refusing to load profiles!")
            return
        for filename in os.listdir(config.profiles_dir):
            # Read bytes from profile file
            path = os.path.join(config.profiles_dir, filename)
            profile = EBPHProfile()
            with open(path, 'rb') as f:
                f.readinto(profile)

            # Update our profile map
            self.bpf["profiles"].__setitem__(ct.c_int64(profile.key), profile)

            logger.debug(f"Successfully loaded profile {profile.comm.decode('utf-8')} ({profile.key})")
        logger.info(f"Successfully loaded all profiles")

    @locks(profiles_lock)
    def fetch_profile(self, key):
        # TODO: check if bpf is None
        return self.bpf['profiles'][ct.c_uint64(key)]

    @locks(processes_lock)
    def fetch_process(self, key):
        # TODO: check if bpf is None
        return self.bpf['processes'][ct.c_uint64(key)]

    @locks(profiles_lock)
    def reset_profile(self, key):
        key = int(key)
        self.stop_monitoring()
        profile = self.bpf['profiles'][ct.c_uint64(key)]
        profile.normal = 0
        profile.frozen = 0
        ct.memset(ct.addressof(profile.train), 0, ct.sizeof(profile.train))
        ct.memset(ct.addressof(profile.test), 0, ct.sizeof(profile.test))
        self.bpf['profiles'][ct.c_uint64(key)] = profile
        self.start_monitoring()

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
        elif attr == 'syscall_count':
            try:
                return self.bpf["stats"][ct.c_uint8(0)].value
            except TypeError:
                return 0
        elif attr == 'monitoring':
            try:
                return bool(self.bpf["__is_monitoring"][0].value)
            except TypeError:
                return False
        return super().__getattribute__(attr)
