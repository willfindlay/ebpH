from http import HTTPStatus
import logging
from typing import List, Dict

from fastapi import FastAPI, HTTPException, Path, Query
from uvicorn.config import LOGGING_CONFIG
import uvicorn

from ebph import defs
from ebph.ebphd import bpf_program
from ebph.structs import EBPH_PROFILE_STATUS, EBPH_SETTINGS
from ebph.utils import ns_to_str, ns_to_delta_str
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


@app.get('/status')
def get_status() -> Dict:
    """
    Returns the status of the BPF program.
    """
    try:
        num_profiles = 0
        num_training = 0
        num_frozen = 0
        num_normal = 0
        for k, v in bpf_program.bpf['profiles'].iteritems():
            num_profiles += 1
            if v.status & EBPH_PROFILE_STATUS.TRAINING:
                num_training += 1
            if v.status & EBPH_PROFILE_STATUS.FROZEN:
                num_frozen += 1
            if v.status & EBPH_PROFILE_STATUS.NORMAL:
                num_normal += 1

        num_processes = 0
        num_threads = 0
        for k, v in bpf_program.bpf['task_states'].iteritems():
            if v.pid == v.tgid:
                num_processes += 1
            num_threads += 1
        res = {
                'Monitoring': bool(bpf_program.get_setting(EBPH_SETTINGS.MONITORING)),
                'Profiles': f'{num_profiles} ({num_training} training, {num_frozen} frozen, {num_normal} normal)',
                'Processes': f'{num_processes} ({num_threads} threads)',
                'Normal Wait': ns_to_delta_str(bpf_program.get_setting(EBPH_SETTINGS.NORMAL_WAIT)),
                'Normal Factor': f'{bpf_program.get_setting(EBPH_SETTINGS.NORMAL_FACTOR)}/'
                                 f'{bpf_program.get_setting(EBPH_SETTINGS.NORMAL_FACTOR_DEN)}',
                'Anomaly Limit': bpf_program.get_setting(EBPH_SETTINGS.ANOMALY_LIMIT),
                }
        return res
    except Exception as e:
        logger.error('', exc_info=e)
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'Unable to get status.')


@app.get('/profiles')
def get_profiles() -> List[Dict]:
    """
    Returns a dictionary of key -> executable.
    """
    try:
        return [get_profile_by_key(k.value) for k in bpf_program.bpf['profiles'].keys()]
    except Exception as e:
        logger.error('', exc_info=e)
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profiles.')


@app.get('/profiles/key/{key}')
def get_profile_by_key(key: int) -> Dict:
    """
    Returns a profile by key.
    """
    try:
        profile = bpf_program.get_profile(key)
        return {
                'exe': str(bpf_program.profile_key_to_exe[key]),
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


@app.get('/profiles/exe/{exe:path}')
def get_profile_by_exe(exe: str) -> Dict:
    """
    Returns a profile by exe.
    """
    rev = {v: k for k, v in bpf_program.profile_key_to_exe.items()}
    try:
        return get_profile_by_key(rev[exe])
    except KeyError as e:
        raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile {exe} does not exist.')
    except Exception as e:
        logger.debug('', exc_info=e)
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profile {exe}.')


@app.put('/profiles/save')
def save_profiles() -> Dict:
    """
    Save profiles.
    """
    saved, error = bpf_program.save_profiles()
    return {'saved': saved, 'error': error}


@app.put('/profiles/load')
def load_profiles() -> Dict:
    """
    Load profiles.
    """
    loaded, error = bpf_program.load_profiles()
    return {'loaded': loaded, 'error': error}


@app.get('/processes')
def get_processes() -> List[Dict]:
    """
    Returns a process by pid.
    """
    processes = []
    for k in bpf_program.bpf['task_states'].keys():
        try:
            processes.append(get_process(k.value))
        except KeyError:
            continue
        except Exception as e:
            logger.debug('', exc_info=e)
            continue
    return processes


@app.get('/processes/pid/{pid}')
def get_process(pid: int) -> Dict:
    """
    Returns a process by pid.
    """
    try:
        process = bpf_program.get_process(pid)
    except KeyError:
        raise HTTPException(HTTPStatus.NOT_FOUND, f'Process {pid} does not exist.')
    except Exception as e:
        logger.debug('', exc_info=e)
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting process {pid}.')
    try:
        profile = get_profile_by_key(process.profile_key)
    except KeyError:
        raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile for {pid} does not exist.')
    except Exception as e:
        logger.debug('', exc_info=e)
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profile for process {pid}.')
    return {
            'pid': process.tgid,
            'tid': process.pid,
            'count': process.count,
            'profile': profile,
            }


@app.get('/settings/{setting}')
def get_setting(setting: EBPH_SETTINGS) -> Dict:
    """
    Get an ebpH setting.
    """
    value = bpf_program.get_setting(setting)
    if value is None:
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'No such setting {setting}.')
    return {'setting': setting, 'value': value}


@app.put('/settings/{setting}/{value}')
def change_setting(setting: EBPH_SETTINGS, value: int = Path(..., ge=0)) -> Dict:
    """
    Change an ebpH setting.
    """
    res = bpf_program.change_setting(setting, value)
    if res < 0:
        raise HTTPException(HTTPStatus.BAD_REQUEST, f'Unable to change {setting} to {value}.')
    return get_setting(setting)
