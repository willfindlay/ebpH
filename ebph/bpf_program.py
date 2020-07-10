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

    def on_tick(self):
        try:
            self.bpf.ring_buffer_consume()
        except Exception:
            pass

    def save_profiles(self):
        pass

    def _register_ring_buffers(self):
        logger.info('Registering ring buffers...')
        logger.error('TODO!')

    def _register_uprobes(self):
        logger.info('Registering uprobes...')
        logger.error('TODO!')

    def _load_bpf(self):
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

        self.bpf = BPF(text=bpf_text, cflags=cflags)
