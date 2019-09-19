import os, sys, socket, signal, time, logging
from threading import Thread
import ctypes as ct

from bcc import BPF, lib

from daemon import Daemon
from config import Config
import utils

TICKSLEEP = 1

BPF_C = utils.path('src/c/bpf.c')
DEFS_H = utils.path('src/c/defs.h')
PROFILES_H = utils.path('src/c/profiles.h')

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
        self.logger.warning("Starting ebpH daemon...")

        # register handlers
        signal.signal(signal.SIGTERM, self.on_term)
        signal.signal(signal.SIGINT, self.on_term)

        if self.monitoring:
            self.start_monitoring()
        while True:
            if self.monitoring:
                self.tick()
            time.sleep(TICKSLEEP)

    def stop(self):
        self.logger.warning("Stopping ebpH daemon...")
        super().stop()

    # BPF stuff below this line --------------------

    def register_perf_buffers(self):
        # profile has been created for the first time
        def on_profile_create(cpu, data, size):
            event = self.bpf["profile_create_event"].event(data)
            s = f"Profile {event.comm.decode('utf-8')} ({event.key}) created."
            self.logger.info(s)
        self.bpf["profile_create_event"].open_perf_buffer(on_profile_create)

        # profile has been loaded for the first time
        def on_profile_load(cpu, data, size):
            event = self.bpf["profile_load_event"].event(data)
            s = f"Profile {event.key} ({event.comm.decode('utf-8')}) loaded."
            self.logger.info(s)
        self.bpf["profile_load_event"].open_perf_buffer(on_profile_load)

        # profile has been reloaded
        def on_profile_reload(cpu, data, size):
            event = self.bpf["profile_load_event"].event(data)
            s = f"Profile {event.key} ({event.comm.decode('utf-8')}) overwritten via load."
            self.logger.info(s)
        self.bpf["profile_reload_event"].open_perf_buffer(on_profile_reload)

        # profile has been associated with a PID
        def on_profile_assoc(cpu, data, size):
            event = self.bpf["profile_assoc_event"].event(data)
            s = f"Profile {event.key} associated with PID {event.pid}."
            self.logger.debug(s)
        self.bpf["profile_assoc_event"].open_perf_buffer(on_profile_assoc)

        # profile has been disasscoated from a PID
        def on_profile_disassoc(cpu, data, size):
            event = self.bpf["profile_disassoc_event"].event(data)
            s = f"Profile {event.key} has been disassociated from PID {event.pid}."
            self.logger.debug(s)
        self.bpf["profile_disassoc_event"].open_perf_buffer(on_profile_disassoc)

        # profile has been copied
        def on_profile_copy(cpu, data, size):
            event = self.bpf["profile_copy_event"].event(data)
            s = f"Profile {event.key} copied from PPID {event.ppid} to PID {event.pid}."
            self.logger.debug(s)
        self.bpf["profile_copy_event"].open_perf_buffer(on_profile_copy)

        # anomaly detected FIXME: not yet implemented
        def on_anomaly(cpu, data, size):
            event = self.bpf["anomaly_event"].event(data)
            s = f"Anomalous systemcall made by process {event.pid} associated with {event.comm.decode('utf-8')} ({event.profile_key})."
            self.logger.warning(s)
        self.bpf["anomaly_event"].open_perf_buffer(on_anomaly)

        # generic warning and debug messages
        def on_error(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.error(s)
        self.bpf["pH_error"].open_perf_buffer(on_error)

        def on_warning(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.logger.warning(s)
        self.bpf["pH_warning"].open_perf_buffer(on_warning)

        def on_debug(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            #event = self.bpf["pH_debug"].event(data)
            s = f"{event}"
            self.logger.debug(s)
        self.bpf["pH_debug"].open_perf_buffer(on_debug)

        self.logger.debug('Registered perf buffers successfully.')

    def start_monitoring(self):
        self.monitoring = True

        # read BPF embedded C from bpf.c
        with open(BPF_C, 'r') as f:
            text = f.read()
            text = text.replace("DEFS_H", DEFS_H, 1)
            text = text.replace("PROFILES_H", PROFILES_H, 1)

        # add flag to load in profiles if save file exists
        if self.check_for_profile_save():
            text = '\n'.join(["#define LOAD_PROFILES", text])

        # compile ebpf code
        self.bpf = BPF(text=text)
        self.register_perf_buffers()

        if self.check_for_profile_save():
            self.logger.info("Loaded profiles successfully.")
            loaded = sorted([''.join([v.comm.decode('utf-8'), ' (', str(v.key), ')']) for v in self.bpf['profile'].values()], key=lambda x: x.upper())
            self.logger.info('\n\t\t\t'.join(['The following profiles have been loaded:'] + loaded))

        # register callback to load profiles
        # FIXME: might fundamentally change how this works, so leaving it commented for now
        #self.bpf.attach_uretprobe(name=defs.LOADER_PATH, sym='load_profile', fn_name='pH_load_profile')

        self.bpf.attach_kretprobe(event='do_open_execat', fn_name='pH_on_do_open_execat')

        self.logger.info('Started monitoring the system.')

    def on_term(self, sn=None, frame=None):
        if self.monitoring:
            self.stop_monitoring()
        sys.exit(0)

    def stop_monitoring(self):
        self.save_profiles()
        self.bpf.cleanup()
        self.bpf = None
        self.monitoring = False

        self.logger.warning('Stopped monitoring the system.')

    # pin a profile map
    def save_profiles(self):
        self.pin_map("profile", dir=Config.ebphfs)

    # Check to see if a savefile exists for profiles
    def check_for_profile_save(self):
        return os.path.exists(os.path.join(Config.ebphfs, 'profile'))

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

        self.bpf.perf_buffer_poll(30)
        self.num_profiles = self.bpf["profiles"].values()[0].value
        self.num_syscalls = self.bpf["syscalls"].values()[0].value
        self.num_forks    = self.bpf["forks"].values()[0].value
        self.num_execves  = self.bpf["execves"].values()[0].value
        self.num_exits    = self.bpf["exits"].values()[0].value

        # debugging stuff
        breakpoint = self.bpf["breakpoint"].values()

        if breakpoint[0].value > 0:
            self.logger.error("Hit the breakpoint on tick {self.ticks}!")
            sys.exit(0)

