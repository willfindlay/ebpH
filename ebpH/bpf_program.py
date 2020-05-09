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

from ebpH.structs import EBPHProfile, EBPHProcess
from ebpH.utils import locks, syscall_name
from ebpH import defs
from ebpH.libebph import libebph

logger = logging.getLogger('ebph')

# Register signal handlers
def handle_sigterm(x, y):
    logger.debug("Caught SIGTERM")
    sys.exit(0)
signal.signal(signal.SIGTERM, handle_sigterm)
def handle_sigint(x, y):
    logger.debug("Caught SIGINT")
    sys.exit(0)
signal.signal(signal.SIGINT, handle_sigint)

class BPFProgram:
    """
    BPFProgram

    Wrapper class to control and provide an interface to the eBPF program.
    """
    monitoring_lock = threading.Lock()
    profiles_lock = threading.Lock()
    processes_lock = threading.Lock()

    def __init__(self, args):
        # Arguments passed in from command line
        self.args = args

        # Should the BPF program debugging information to debugfs and read it into the logs?
        self.debug = self.args.debug

        # Should we save or load profiles?
        self.should_save = not self.args.nosave
        self.should_load = not self.args.noload

        # BPF program should be None until it is loaded
        self.bpf = None

    def cleanup(self):
        """
        Cleanup hook for BPF program.
        Stops monitoring the system and then saves all profiles.
        Finally, sets BPF program to None and prints information to logs.
        """
        logger.info('Running cleanup hooks...')
        self.stop_monitoring()
        self.save_profiles()
        self.bpf = None
        logger.info('BPF program unloaded')

    def register_exit_hooks(self):
        """
        Register the cleanup function as an exit hook.
        """
        # Unregister bcc's cleanup function, which was causing segmentation fault
        # TODO: figure out a) why this was happening; and b) whether or not this is okay to do
        atexit.unregister(self.bpf.cleanup)
        # Unregister our own cleanup if already registered
        atexit.unregister(self.cleanup)
        # Register out own cleanup
        atexit.register(self.cleanup)
        logger.info("Registered BPFProgram exit hooks")

    def register_perf_buffers(self):
        """
        Register perf buffers for returning information to userspace from BPF program.
        All perf buffer handlers are defined as closures in here.
        """
        def lost_cb(buff_name):
            """
            Returns a closure that prints more detailed information on lost samples.
            """
            def closure(lost):
                logger.warning(f"Lost {lost} samples from perf_buffer {buff_name}")
            return closure

        def on_executable_processed(cpu, data, size):
            """
            Invoked every time an executable is processed in the BPF program.
            Events are submitted in kretprobe___on_startdo_open_execat.
            """
            event = self.bpf["on_executable_processed"].event(data)
            s = f"Constructed profile for {event.comm.decode('utf-8')} ({event.key})"
            logger.info(s)
        self.bpf["on_executable_processed"].open_perf_buffer(on_executable_processed, lost_cb=lost_cb("on_executable_processed"))

        def on_anomaly(cpu, data, size):
            """
            Invoked every time an anaomaly is detected by the BPF program.
            Events are submitted in ebpH_process_normal.
            """
            process = ct.cast(data, ct.POINTER(EBPHProcess)).contents
            try:
                profile = self.bpf["profiles"][ct.c_uint64(process.profile_key)]
            except KeyError:
                profile = EBPHProfile()
                profile.key = process.profile_key
                profile.comm = b'UNKNOWN'

            # Get sequence array from correct stack frame
            sequence = process.stack.seq[process.stack.top].seq
            # 9999 is empty
            sequence = [syscall_name(syscall) for syscall in sequence if syscall != 9999]
            # Sequences are actually reversed
            sequence = reversed(sequence)

            logger.warning(f"Anomalies in PID {process.pid} ({profile.comm.decode('utf-8')} {profile.key}): {', '.join(sequence)}")
            logger.debug(f"Stack top: {process.stack.top}")
        self.bpf["on_anomaly"].open_perf_buffer(on_anomaly, lost_cb=lost_cb("on_anomaly"))

        def on_anomaly_limit(cpu, data, size):
            """
            Invoked every time a profile exceeds its anomaly limit.
            Events are submitted in ebpH_process_normal.
            """
            process = ct.cast(data, ct.POINTER(EBPHProcess)).contents
            try:
                profile = self.bpf["profiles"][ct.c_uint64(process.profile_key)]
            except KeyError:
                profile = EBPHProfile()
                profile.key = process.profile_key
                profile.comm = b'UNKNOWN'

            logger.warning(f"Anomaly limit exceeded in PID {process.pid} ({profile.comm.decode('utf-8')} {profile.key}), stopping normal monitoring")
        self.bpf["on_anomaly_limit"].open_perf_buffer(on_anomaly_limit, lost_cb=lost_cb("on_anomaly_limit"))

        def on_tolerize_limit(cpu, data, size):
            """
            Invoked every time a process exceeds its tolerize limit.
            Events are submitted in ebpH_process_normal.
            """
            process = ct.cast(data, ct.POINTER(EBPHProcess)).contents
            try:
                profile = self.bpf["profiles"][ct.c_uint64(process.profile_key)]
            except KeyError:
                profile = EBPHProfile()
                profile.key = process.profile_key
                profile.comm = b'UNKNOWN'

            logger.warning(f"Tolerize limit exceeded in PID {process.pid} ({profile.comm.decode('utf-8')} {profile.key}), resetting training data")
        self.bpf["on_tolerize_limit"].open_perf_buffer(on_tolerize_limit, lost_cb=lost_cb("on_tolerize_limit"))

        def on_start_normal(cpu, data, size):
            """
            Invoked every time a profile is made normal.
            Events are submitted in ebpH_start_normal.
            """
            process = ct.cast(data, ct.POINTER(EBPHProcess)).contents
            try:
                profile = self.bpf["profiles"][ct.c_uint64(process.profile_key)]
            except KeyError:
                profile = EBPHProfile()
                profile.key = process.profile_key
                profile.comm = b'UNKNOWN'

            logger.info(f"{profile.comm.decode('utf-8')} ({profile.key}) now has {profile.test.train_count} training calls and {profile.test.last_mod_count} since last change")
            logger.info(f"Starting normal monitoring in PID {process.pid} ({profile.comm.decode('utf-8')} {profile.key}) with {profile.train.sequences} sequences")
        self.bpf["on_start_normal"].open_perf_buffer(on_start_normal, lost_cb=lost_cb("on_start_normal"))

        def on_new_sequence(cpu, data, size):
            """
            Invoked every time a new sequence is detected by the BPF program
            and we have set logging_new_sequences to 1.
            Events are submitted in ebpH_train.
            """
            process = ct.cast(data, ct.POINTER(EBPHProcess)).contents
            try:
                profile = self.bpf["profiles"][ct.c_uint64(process.profile_key)]
            except KeyError:
                profile = EBPHProfile()
                profile.key = process.profile_key
                profile.comm = b'UNKNOWN'

            # Get sequence array from correct stack frame
            sequence = process.stack.seq[process.stack.top].seq
            # 9999 is empty
            sequence = [syscall_name(syscall) for syscall in sequence if syscall != 9999]
            # Sequences are actually reversed
            sequence = reversed(sequence)

            logger.info(f"New seq in PID {process.pid} ({profile.comm.decode('utf-8')} {profile.key}): {', '.join(sequence)}")
            logger.debug(f"Stack top: {process.stack.top}")
        self.bpf["on_new_sequence"].open_perf_buffer(on_new_sequence, lost_cb=lost_cb("on_new_sequence"), page_cnt=2**8)

        def ebpH_error(cpu, data, size):
            """
            Generic function for returning simple error messages to userspace.
            Events are submitted at various points of failure in the eBPF program.

            For more detailed error reporting, use the --debug flag instead when starting the daemon.
            """
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            logger.error(s)
        self.bpf["ebpH_error"].open_perf_buffer(ebpH_error, lost_cb=lost_cb("ebpH_error"))

        def ebpH_warning(cpu, data, size):
            """
            Generic function for returning simple warning messages to userspace.
            Currently not used.
            """
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            logger.warning(s)
        self.bpf["ebpH_warning"].open_perf_buffer(ebpH_warning, lost_cb=lost_cb("ebpH_warning"))

        logger.info(f'Registered perf buffers')

    def register_uprobes(self):
        libebph.register_uprobes(self.bpf)
        logger.info('Registered uprobes')

    def load_bpf(self):
        """
        Load BPF program and performs various setup functionality.

        In order we:
            1. Set up our cflags.
            2. Calculate boot epoch time and set it as a flag.
            3. Open the bpf program for reading.
            4. Compile and load the BPF program, passing the flags we set previously.
            5. Register exit hooks.
            6. Register perf buffers.
            7. Load profiles (if we should load).
            8. Start monitoring the system.
        """
        assert self.bpf == None
        logger.info('Initializing BPF program...')

        # Set flags
        flags = []
        if self.debug:
            flags.append("-DEBPH_DEBUG")
        if self.args.ludikris:
            flags.append("-DLUDIKRIS")
        for k, v in defs.bpf_params.items():
            # Correctly handle string arguments
            if type(v) == str:
                v = f"\"{v}\""
            logger.info(f"Using {k}={v}...")
            flags.append(f"-D{k}={v}")
        # Include project src
        flags.append(f"-I{defs.project_path}/ebpH")
        # Estimate epoch boot time.
        # This is used to establish normal times within the BPF program
        # since eBPF only provides times since system boot.
        boot_time = time.monotonic() * 1000000000
        boot_epoch = time.time() * 1000000000 - boot_time
        flags.append(f"-DEBPH_BOOT_EPOCH=(u64){boot_epoch}")

        # Compile and load eBPF program
        with open(defs.bpf_program, "r") as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=flags)

        # Regiter exit hooks and perf buffers
        self.register_exit_hooks()
        self.register_perf_buffers()
        self.register_uprobes()

        self.load_profiles()
        self.start_monitoring()

        if defs.log_new_sequences:
            self.start_logging_new_sequences()

        logger.info('BPF program initialized')

    def trace_print(self):
        """
        Helper to print information from debugfs logfile until we have consumed it entirely.

        This is great for debugging, but should not be used in production, since the debugfs logfile
        is shared globally between all BPF programs.
        """
        while True:
            try:
                fields = self.bpf.trace_fields(nonblocking=True)
                msg = fields[-1]
                if msg == None:
                    return
                logger.debug(msg.decode('utf-8'))
            except:
                logger.warning("Could not correctly parse debug information from debugfs")

    def on_tick(self):
        """
        This function is executed continuously as the daemon runs.
        Implements a "tick", polling perf buffers and optionally parsing debugfs logs.
        """
        self.bpf.perf_buffer_poll(30)
        if self.debug:
            self.trace_print()

# Commands below this line ----------------------------------------------

    def set_logging_new_sequences(self, should_log):
        """
        Start or stop logging new sequences.
        """
        if should_log:
            return self.start_logging_new_sequences()
        else:
            return self.stop_logging_new_sequences()

    def start_logging_new_sequences(self):
        """
        Start logging new sequences.
        """
        if self.logging_new_sequences:
            msg = 'New sequences are already being logged'
            logger.info(msg)
            return msg
        self.bpf["__is_logging_new_sequences"][ct.c_int(0)] = ct.c_int(1)
        msg = f'Started logging new sequences to {defs.newseq_logfile}'
        logger.info(msg)
        return msg

    def stop_logging_new_sequences(self):
        """
        Stop logging new sequences.
        """
        if not self.logging_new_sequences:
            msg = 'New sequences are not currently being logged'
            logger.info(msg)
            return msg
        self.bpf["__is_logging_new_sequences"][ct.c_int(0)] = ct.c_int(0)
        msg = f'Stopped logging new sequences'
        logger.info(msg)
        return msg

    @locks(monitoring_lock)
    def start_monitoring(self):
        """
        Start monitoring the system.
        """
        if self.monitoring:
            msg = 'System is already being monitored'
            logger.info(msg)
            return msg
        self.bpf["__is_monitoring"][ct.c_int(0)] = ct.c_int(1)
        msg = 'Started monitoring the system'
        logger.info(msg)
        return msg

    @locks(monitoring_lock)
    def stop_monitoring(self):
        """
        Stop monitoring the system.
        """
        if not self.monitoring:
            msg = 'System is not being monitored'
            logger.info(msg)
            return msg
        self.bpf["__is_monitoring"][ct.c_int(0)] = ct.c_int(0)
        msg ='Stopped monitoring the system'
        logger.info(msg)
        return msg

    @locks(profiles_lock)
    def save_profiles(self):
        """
        Save all profiles to disk, if configured to save.
        """
        if not self.should_save:
            msg = 'should_save is false, refusing to save profiles!'
            logger.warning(msg)
            return msg
        # Notify BPF program that we are saving
        self.bpf["__is_saving"][ct.c_int(0)] = ct.c_int(1)
        # Wait until bpf knows it is saving
        while not self.bpf["__is_saving"][0]:
            pass
        # Must be itervalues, not values
        for profile in self.bpf["profiles"].itervalues():
            path = os.path.join(defs.profiles_dir, str(profile.key))
            # Make sure that the files are only readable and writable by root
            with open(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600), 'wb') as f:
                f.write(profile)
            # Just in case the file already existed with the wrong permissions
            os.chmod(path, 0o600)
            logger.debug(f"Successfully saved profile {profile.comm.decode('utf-8')} ({profile.key})")
        # return to original state
        self.bpf["__is_saving"][ct.c_int(0)] = ct.c_int(0)
        # Notify user
        msg = "Successfully saved all profiles"
        logger.info(msg)
        return msg

    # load all profiles from disk
    @locks(profiles_lock)
    def load_profiles(self):
        """
        Load all profiles from disk, if configured to load.
        """
        if not self.should_load:
            msg = 'should_load is false, refusing to load profiles!'
            logger.warning(msg)
            return msg
        for filename in os.listdir(defs.profiles_dir):
            # Read bytes from profile file
            path = os.path.join(defs.profiles_dir, filename)
            profile = EBPHProfile()
            with open(path, 'rb') as f:
                f.readinto(profile)
            # Update our profile map
            self.bpf["profiles"][ct.c_uint64(profile.key)] = profile
            logger.debug(f"Successfully loaded profile {profile.comm.decode('utf-8')} from {path}")
        # Notify user
        msg = 'Successfully loaded all profiles'
        logger.info(msg)
        return msg

    def is_monitoring(self):
        """
        Return true if we are monitoring, else false.
        """
        return self.monitoring

    def status(self):
        """
        Return a dictionary of basic information about ebphd's state.
        """
        status = {
                'Monitoring': self.monitoring,
                'Profiles': self.profile_count,
                'TasksMonitored': self.process_count,
                'SyscallsCount': self.syscall_count,
                }
        return status

    # TODO: Move all of the following json logic into either:
    # The the routes in api.py
    # Or new serialize methods in structs.py
    # Not sure which approach is best, implicit conversion when reading maps will be
    # annoying for the structs.py option

    @locks(profiles_lock)
    def get_profile(self, key):
        """
        Return a dictionary of basic profile info excluding things like lookahead pairs.
        """
        try:
            profile = self.bpf['profiles'][ct.c_uint64(key)]
        except KeyError:
            return None
        data = profile.train
        attrs = {
                'comm': profile.comm.decode('utf-8'),
                'key': profile.key,
                'frozen': profile.frozen,
                'normal': profile.normal,
                'normal_time': profile.normal_time,
                'last_mod_count': data.last_mod_count,
                'train_count': data.train_count,
                'count': profile.count,
                'sequences': data.sequences,
                'anomalies': profile.anomalies,
                }
        return attrs

    @locks(processes_lock)
    def get_process(self, key):
        """
        Return a dictionary of basic process info, including the accompanying profile.
        """
        try:
            process = self.bpf['processes'][ct.c_uint64(key)]
        except KeyError:
            return None
        attrs = {
                'pid': process.pid,
                'tid': process.tid,
                'profile_key': process.profile_key,
                'profile': self.get_profile(process.profile_key),
                }
        return attrs

    def get_profiles(self):
        """
        Return profile info for all profiles.
        """
        profiles = {}
        for k in self.bpf["profiles"].keys():
            k = k.value
            profiles[k] = self.get_profile(k)
        return profiles

    def get_processes(self):
        """
        Return process info for all processes.
        """
        processes = {}
        for k in self.bpf["processes"].keys():
            k = k.value
            try:
                processes[k] = self.get_process(k)
            except KeyError:
                pass
        return processes

    @locks(profiles_lock)
    def normalize_process(self, tid):
        """
        Start normal mode on a profile attached to process with <tid>.
        """
        return libebph.libebph.cmd_normalize_process(ct.c_uint32(tid))

    @locks(profiles_lock)
    def reset_profile(self, key):
        """
        Reset a profile. WARNING: not yet working 100%
        """
        # TODO: implement this in bpf program
        return libebph.libebph.cmd_reset_profile(ct.c_uint64(key))

    #def get_full_profile(self, key):
    #    """
    #    Return a dictionary of ALL profile info, including things like lookahead pairs.
    #    """
    #    key = int(key)
    #    profile = self.get_profile(key)
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
        elif attr == 'logging_new_sequences':
            try:
                return bool(self.bpf["__is_logging_new_sequences"][0].value)
            except TypeError:
                return False
        return super().__getattribute__(attr)
