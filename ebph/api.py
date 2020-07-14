import logging

from fastapi import FastAPI
from uvicorn.config import LOGGING_CONFIG
import uvicorn

from ebph import defs
from ebph.ebphd import bpf_program
from ebph.profile import EBPH_PROFILE_STATUS
from ebph.utils import ns_to_str
from ebph.logger import get_logger

app = FastAPI()

logger = get_logger()

# Monkeypatch uvicorn to not hijack root logger
try:
    LOGGING_CONFIG['loggers']['uvicorn'] = LOGGING_CONFIG['loggers']['']
    del LOGGING_CONFIG['loggers']['']
except KeyError:
    pass


def serve_forever():
    uvicorn.run(
        app,
        host='localhost',
        port=defs.EBPH_PORT,
        log_level=logging.WARNING,
        log_config=LOGGING_CONFIG,
    )


@app.get('/profiles/{key}')
def _num_profiles(key: int):
    try:
        profile = bpf_program.get_profile(int(key))
        return {
                'profile_key': key,
                'exe': bpf_program.profile_key_to_exe[key],
                'status': str(EBPH_PROFILE_STATUS(profile.status)),
                'anomaly_count': profile.anomaly_count,
                'train_count': profile.train_count,
                'last_mod_count': profile.last_mod_count,
                'sequences': profile.sequences,
                'normal_time': ns_to_str(profile.normal_time),
                }
    except Exception as e:
        logger.error('', exc_info=e)
        return None
