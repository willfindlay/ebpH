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
        self._load_bpf()
        self._register_ring_buffers()
        self._register_uprobes()
        self.profile_key_to_exe = {}

    def on_tick(self) -> None:
        try:
            self.bpf.ring_buffer_consume()
        except Exception:
            pass

    def save_profiles(self) -> None:
        pass

    def _register_ring_buffers(self) -> None:
        logger.info('Registering ring buffers...')

        @ringbuf_callback(self.bpf, 'new_profile_events')
        def new_profile_events(ctx, event, size):
            pathname = event.pathname.decode('utf-8')

            self.profile_key_to_exe[event.profile_key] = pathname

            logger.info(f'Created new profile for {pathname}.')

    def _register_uprobes(self) -> None:
        logger.info('Registering uprobes...')
        logger.error('TODO!')

    def _generate_syscall_defines(self, flags: List[str]) -> None:
        from bcc.syscall import syscalls
        for num, name in syscalls.items():
            name = name.decode('utf-8').upper()
            definition = f'-DEBPH_SYS_{name}={num}'
            flags.append(definition)

    def _load_bpf(self) -> None:
        assert self.bpf is None
        logger.info('Loading BPF program...')

        with open(defs.BPF_PROGRAM_C, 'r') as f:
            bpf_text = f.read()

        cflags = []
        cflags.append(f'-I{defs.BPF_DIR}')
        for k, v in defs.BPF_DEFINES.items():
            cflags.append(f'-D{k}={v}')

        for flag in cflags:
            logger.debug(f'Using {flag}...')

        self._generate_syscall_defines(cflags)

        self.bpf = BPF(text=bpf_text, cflags=cflags)
