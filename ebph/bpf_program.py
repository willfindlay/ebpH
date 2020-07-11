import time
import atexit
import ctypes as ct
from collections import defaultdict
from typing import List

from bcc import BPF

from ebph.logger import get_logger
from ebph import defs

logger = get_logger()

def ringbuf_callback(bpf, map_name, infer_type=True):
    def _inner(func):
        def _wrapper(ctx, data, size):
            if infer_type:
                data = bpf[map_name].event(data)
            func(ctx, data, size)

        bpf[map_name].open_ring_buffer(_wrapper)

    return _inner

class BPFProgram:
    def __init__(self, debug=False):
        self.bpf = None
        self.seqstack_inner_bpf = None
        self.cflags = []
        self.debug = debug

        self.profile_key_to_exe = defaultdict(lambda: None)
        self.syscall_number_to_name = defaultdict(lambda: '[unknown]')

        self._set_cflags()
        self._load_bpf()
        self._register_ring_buffers()
        self._register_uprobes()

    def on_tick(self) -> None:
        try:
            self.bpf.ring_buffer_consume()
            #logger.debug(len(self.bpf['seqstacks']))
        except Exception:
            pass

    def save_profiles(self) -> None:
        pass

    def _register_ring_buffers(self) -> None:
        logger.info('Registering ring buffers...')

        @ringbuf_callback(self.bpf, 'new_profile_events')
        def new_profile_events(ctx, event, size):
            """
            new_profile_events.

            Callback for new profile creation.
            Logs creation and caches key -> pathname mapping
            for later use.
            """
            pathname = event.pathname.decode('utf-8')

            self.profile_key_to_exe[event.profile_key] = pathname

            if self.debug:
                logger.info(f'Created new profile for {pathname} ({event.profile_key}).')
            else:
                logger.info(f'Created new profile for {pathname}.')

        @ringbuf_callback(self.bpf, 'anomaly_events')
        def anomaly_events(ctx, event, size):
            """
            anomaly_events.

            Log anomalies.
            """
            exe = self.profile_key_to_exe[event.profile_key]
            syscall_number = event.syscall
            syscall_name = self.syscall_number_to_name[syscall_number]
            misses = event.misses
            pid = event.pid
            count = event.task_count

            logger.warning(f'Anomalous {syscall_name} ({misses} misses) '
                    f'in PID {pid} ({exe}) after {count} calls.')

        @ringbuf_callback(self.bpf, 'start_normal_events')
        def start_normal_events(ctx, event, size):
            """
            start_normal_events.

            Log when a profile starts normal monitoring.
            """
            exe = self.profile_key_to_exe[event.profile_key]
            profile_count = event.profile_count
            sequences = event.sequences
            train_count = event.train_count
            last_mod_count = event.last_mod_count

            in_task = event.in_task
            task_count = event.task_count
            pid = event.pid

            if in_task:
                logger.info(f'PID {pid} ({exe}) now has {train_count} '
                        f'training calls and {last_mod_count} since last '
                        f'change ({profile_count} total).')
                logger.info(f'Starting normal monitoring in PID {pid} ({exe}) '
                        f'after {task_count} calls ({sequences} sequences).')
            else:
                logger.info(f'{exe} now has {train_count} '
                        f'training calls and {last_mod_count} since last '
                        f'change ({profile_count} total).')
                logger.info(f'Starting normal monitoring for {exe} '
                        f'with {sequences} sequences.')

        @ringbuf_callback(self.bpf, 'stop_normal_events')
        def stop_normal_events(ctx, event, size):
            """
            stop_normal_events.

            Log when a profile stops normal monitoring.
            """
            exe = self.profile_key_to_exe[event.profile_key]
            anomalies = event.anomalies
            anomaly_limit = event.anomaly_limit

            in_task = event.in_task
            task_count = event.task_count
            pid = event.pid

            if in_task:
                logger.info(f'Stopped normal monitoring in PID {pid} ({exe}) '
                        f'after {task_count} calls and {anomalies} anomalies '
                        f'(limit {anomaly_limit}).')
            else:
                logger.info(f'Stopped normal monitoring for {exe} '
                        f'with {anomalies} anomalies (limit {anomaly_limit}).')

        if not self.debug:
            return

        @ringbuf_callback(self.bpf, 'new_task_state_events')
        def new_task_state_events(ctx, event, size):
            """
            new_task_state_events.

            Callback for new process creation.
            """
            pid = event.pid
            profile_key = event.profile_key
            exe = self.profile_key_to_exe[profile_key]

            logger.debug(f'Created new task_state for PID {pid} ({exe}).')

    def _register_uprobes(self) -> None:
        logger.info('Registering uprobes...')
        logger.error('TODO!')

    def _generate_syscall_defines(self, flags: List[str]) -> None:
        from bcc.syscall import syscalls
        for num, name in syscalls.items():
            name = name.decode('utf-8').upper()
            self.syscall_number_to_name[num] = name
            definition = f'-DEBPH_SYS_{name}={num}'
            flags.append(definition)

    def _calculate_boot_epoch(self):
        boot_time = time.monotonic() * int(1e9)
        boot_epoch = time.time() * int(1e9) - boot_time
        return boot_epoch

    def _set_cflags(self) -> None:
        logger.info('Setting cflags...')

        self.cflags.append(f'-I{defs.BPF_DIR}')
        for k, v in defs.BPF_DEFINES.items():
            self.cflags.append(f'-D{k}={v}')

        if self.debug:
            self.cflags.append('-DEBPH_DEBUG')

        for flag in self.cflags:
            logger.debug(f'Using {flag}...')

        self.cflags.append(f'-DEBPH_BOOT_EPOCH=((u64){self._calculate_boot_epoch()})')
        self._generate_syscall_defines(self.cflags)

    def _load_bpf(self) -> None:
        assert self.bpf is None
        logger.info('Loading BPF program...')

        with open(defs.BPF_PROGRAM_C, 'r') as f:
            bpf_text = f.read()

        self.bpf = BPF(text=bpf_text, cflags=self.cflags)
        # FIXME: BPF cleanup function is segfaulting, so unregister it for now.
        # It actually doesn't really do anything particularly useful.
        atexit.unregister(self.bpf.cleanup)

