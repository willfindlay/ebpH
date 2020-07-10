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
    def __init__(self):
        self.bpf = None
        self.seqstack_inner_bpf = None
        self.cflags = []
        self._set_cflags()
        self._load_bpf()
        self._register_ring_buffers()
        self._register_uprobes()
        self.profile_key_to_exe = defaultdict(lambda: None)

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

            logger.info(f'Created new profile for {pathname}.')

        @ringbuf_callback(self.bpf, 'new_task_state_events')
        def new_task_state_events(ctx, event, size):
            """
            new_task_state_events.

            Callback for new process creation.
            """
            pid = ct.c_uint32(event.pid)
            profile_key = ct.c_uint64(event.profile_key)

            exe = self.profile_key_to_exe[event.profile_key]

            logger.debug(f'Created new task_state for PID {event.pid} ({exe}).')

    def _register_uprobes(self) -> None:
        logger.info('Registering uprobes...')
        logger.error('TODO!')

    def _generate_syscall_defines(self, flags: List[str]) -> None:
        from bcc.syscall import syscalls
        for num, name in syscalls.items():
            name = name.decode('utf-8').upper()
            definition = f'-DEBPH_SYS_{name}={num}'
            flags.append(definition)

    def _set_cflags(self) -> None:
        logger.info('Setting cflags...')

        self.cflags.append(f'-I{defs.BPF_DIR}')
        for k, v in defs.BPF_DEFINES.items():
            self.cflags.append(f'-D{k}={v}')

        for flag in self.cflags:
            logger.debug(f'Using {flag}...')

        self._generate_syscall_defines(self.cflags)

    def _load_bpf(self) -> None:
        assert self.bpf is None
        logger.info('Loading BPF program...')

        with open(defs.BPF_PROGRAM_C, 'r') as f:
            bpf_text = f.read()

        self.bpf = BPF(text=bpf_text, cflags=self.cflags)

