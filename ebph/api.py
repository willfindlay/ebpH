from http import HTTPStatus
import logging

from fastapi import FastAPI, HTTPException
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


@app.get('/profiles')
def _get_profiles():
    try:
        return bpf_program.get_profiles()
    except Exception as e:
        logger.error('', exc_info=e)
        return None


@app.get('/profiles/key/{key}')
def _get_profile_key(key: int):
    try:
        profile = bpf_program.get_profile(int(key))
        return {
                'exe': bpf_program.profile_key_to_exe[key],
                'profile_key': key,
                'status': str(EBPH_PROFILE_STATUS(profile.status)),
                'anomaly_count': profile.anomaly_count,
                'count': profile.count,
                'train_count': profile.train_count,
                'last_mod_count': profile.last_mod_count,
                'sequences': profile.sequences,
                'normal_time': ns_to_str(profile.normal_time),
                }
    except KeyError:
        raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile {key} does not exist.')
    except Exception as e:
        logger.debug('', exc_info=e)
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profile {key}.')


@app.get('/profiles/exe/{exe}')
def _get_profile_exe(exe: str):
    rev = {v: k for k, v in _get_profiles().items()}
    try:
        return _get_profile_key(rev[exe])
    except KeyError as e:
        raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile {exe} does not exist.')
    except Exception as e:
        logger.debug('', exc_info=e)
        return None
