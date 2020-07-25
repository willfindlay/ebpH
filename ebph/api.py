"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Uses FastAPI to provide a REST API for interacting with the daemon.

    2020-Jul-13  William Findlay  Created this.
"""

from http import HTTPStatus
import logging
from typing import List, Dict, NoReturn

from fastapi import FastAPI, HTTPException, Path, Query
from uvicorn.config import LOGGING_CONFIG
import uvicorn

from ebph import defs
from ebph.bpf_program import BPFProgram
from ebph.structs import EBPH_PROFILE_STATUS, EBPH_SETTINGS
from ebph.utils import ns_to_str, ns_to_delta_str
from ebph.version import __version__
from ebph.logger import get_logger

app = FastAPI()
logger = get_logger()

# Monkeypatch uvicorn to not hijack root logger
try:
    LOGGING_CONFIG['loggers']['uvicorn'] = LOGGING_CONFIG['loggers']['']
    del LOGGING_CONFIG['loggers']['']
except KeyError:
    pass

class API:
    bpf_program: BPFProgram = None

    @classmethod
    def connect_bpf_program(cls, bpf_program: BPFProgram) -> None:
        cls.bpf_program = bpf_program

    @staticmethod
    def serve_forever() -> NoReturn:
        uvicorn.run(
            app,
            #host='localhost',
            #port=defs.EBPH_PORT,
            uds=defs.EBPH_SOCK,
            log_level=logging.WARNING,
            log_config=LOGGING_CONFIG,
        )

    @staticmethod
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
            for k, v in API.bpf_program.bpf['profiles'].iteritems():
                num_profiles += 1
                if v.status & EBPH_PROFILE_STATUS.TRAINING:
                    num_training += 1
                if v.status & EBPH_PROFILE_STATUS.FROZEN:
                    num_frozen += 1
                if v.status & EBPH_PROFILE_STATUS.NORMAL:
                    num_normal += 1

            num_processes = 0
            num_threads = 0
            for k, v in API.bpf_program.bpf['task_states'].iteritems():
                if v.pid == v.tgid:
                    num_processes += 1
                num_threads += 1
            res = {
                    'ebpH Version': __version__,
                    'Monitoring': bool(API.bpf_program.get_setting(EBPH_SETTINGS.MONITORING)),
                    'Logging New Seq': bool(API.bpf_program.get_setting(EBPH_SETTINGS.LOG_SEQUENCES)),
                    'Profiles': f'{num_profiles} ({num_training} training ({num_frozen} frozen), {num_normal} normal)',
                    'Processes': f'{num_processes} ({num_threads} threads)',
                    'Normal Wait': ns_to_delta_str(API.bpf_program.get_setting(EBPH_SETTINGS.NORMAL_WAIT)),
                    'Normal Factor': f'{API.bpf_program.get_setting(EBPH_SETTINGS.NORMAL_FACTOR)}/'
                                     f'{API.bpf_program.get_setting(EBPH_SETTINGS.NORMAL_FACTOR_DEN)}',
                    'Anomaly Limit': API.bpf_program.get_setting(EBPH_SETTINGS.ANOMALY_LIMIT),
                    'Tolerize Limit': API.bpf_program.get_setting(EBPH_SETTINGS.TOLERIZE_LIMIT),
                    }
            return res
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Unable to get status.')

    @staticmethod
    @app.get('/profiles')
    def get_profiles() -> List[Dict]:
        """
        Returns a dictionary of key -> executable.
        """
        try:
            return [API.get_profile_by_key(k.value) for k in API.bpf_program.bpf['profiles'].keys()]
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profiles.')

    @staticmethod
    @app.get('/profiles/key/{key}')
    def get_profile_by_key(key: int) -> Dict:
        """
        Returns a profile by @key.
        """
        try:
            profile = API.bpf_program.get_profile(key)
            return {
                    'exe': str(API.bpf_program.profile_key_to_exe[key]),
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
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profile {key}.')

    @staticmethod
    @app.get('/profiles/exe/{exe:path}')
    def get_profile_by_exe(exe: str) -> Dict:
        """
        Returns a profile by @exe.
        """
        rev = {v: k for k, v in API.bpf_program.profile_key_to_exe.items()}
        try:
            return API.get_profile_by_key(rev[exe])
        except KeyError as e:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile {exe} does not exist.')
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profile {exe}.')

    @staticmethod
    @app.put('/profiles/key/{key}/normalize')
    def normalize_profile_by_key(key: int) -> Dict:
        """
        Normalize a profile by its @key.
        """
        try:
            rc = API.bpf_program.normalize_profile(key)
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error normalizing profile {key}.')
        if rc < 0:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Unable to normalize profile {key}.')
        return API.get_profile_by_key(key)

    @staticmethod
    @app.put('/profiles/exe/{exe:path}/normalize')
    def normalize_profile_by_exe(exe: str) -> Dict:
        """
        Normalize a profile by its @exe.
        """
        rev = {v: k for k, v in API.bpf_program.profile_key_to_exe.items()}
        try:
            return API.normalize_profile_by_key(rev[exe])
        except KeyError as e:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile {exe} does not exist.')
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error normalizing profile {exe}.')

    @staticmethod
    @app.put('/processes/pid/{pid}/normalize')
    def normalize_process(pid: int) -> Dict:
        """
        Normalize a profile by its @pid.
        """
        try:
            rc = API.bpf_program.normalize_process(pid)
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error normalizing process {pid}.')
        if rc < 0:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Unable to normalize process {pid}.')
        return API.get_process(pid)

    @staticmethod
    @app.put('/profiles/key/{key}/sensitize')
    def sensitize_profile_by_key(key: int) -> Dict:
        """
        Normalize a profile by its @key.
        """
        try:
            rc = API.bpf_program.sensitize_profile(key)
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error normalizing profile {key}.')
        if rc < 0:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Unable to sensitize profile {key}.')
        return API.get_profile_by_key(key)

    @staticmethod
    @app.put('/profiles/exe/{exe:path}/sensitize')
    def sensitize_profile_by_exe(exe: str) -> Dict:
        """
        Normalize a profile by its @exe.
        """
        rev = {v: k for k, v in API.bpf_program.profile_key_to_exe.items()}
        try:
            return API.sensitize_profile_by_key(rev[exe])
        except KeyError as e:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile {exe} does not exist.')
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error sensitizing profile {exe}.')

    @staticmethod
    @app.put('/processes/pid/{pid}/sensitize')
    def sensitize_process(pid: int) -> Dict:
        """
        Normalize a profile by its @pid.
        """
        try:
            rc = API.bpf_program.sensitize_process(pid)
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error sensitizing process {pid}.')
        if rc < 0:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Unable to sensitize process {pid}.')
        return API.get_process(pid)

    @staticmethod
    @app.put('/profiles/key/{key}/tolerize')
    def tolerize_profile_by_key(key: int) -> Dict:
        """
        Normalize a profile by its @key.
        """
        try:
            rc = API.bpf_program.tolerize_profile(key)
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error tolerizing profile {key}.')
        if rc < 0:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Unable to tolerize profile {key}.')
        return API.get_profile_by_key(key)

    @staticmethod
    @app.put('/profiles/exe/{exe:path}/tolerize')
    def tolerize_profile_by_exe(exe: str) -> Dict:
        """
        Normalize a profile by its @exe.
        """
        rev = {v: k for k, v in API.bpf_program.profile_key_to_exe.items()}
        try:
            return API.tolerize_profile_by_key(rev[exe])
        except KeyError as e:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile {exe} does not exist.')
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error tolerizing profile {exe}.')

    @staticmethod
    @app.put('/processes/pid/{pid}/tolerize')
    def tolerize_process(pid: int) -> Dict:
        """
        Normalize a profile by its @pid.
        """
        try:
            rc = API.bpf_program.tolerize_process(pid)
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error tolerizing process {pid}.')
        if rc < 0:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Unable to tolerize process {pid}.')
        return API.get_process(pid)

    @staticmethod
    @app.put('/profiles/save')
    def save_profiles() -> Dict:
        """
        Save profiles.
        """
        saved, error = API.bpf_program.save_profiles()
        return {'saved': saved, 'error': error}

    @staticmethod
    @app.put('/profiles/load')
    def load_profiles() -> Dict:
        """
        Load profiles.
        """
        loaded, error = API.bpf_program.load_profiles()
        return {'loaded': loaded, 'error': error}

    @staticmethod
    @app.get('/processes')
    def get_processes() -> List[Dict]:
        """
        Returns a process by pid.
        """
        processes = []
        for k in API.bpf_program.bpf['task_states'].keys():
            try:
                processes.append(API.get_process(k.value))
            except (KeyError, HTTPException):
                continue
            except Exception as e:
                logger.error('', exc_info=e)
                continue
        return processes

    @staticmethod
    @app.get('/processes/pid/{pid}')
    def get_process(pid: int) -> Dict:
        """
        Returns a process by pid.
        """
        try:
            process = API.bpf_program.get_process(pid)
        except KeyError:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Process {pid} does not exist.')
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting process {pid}.')
        try:
            profile = API.get_profile_by_key(process.profile_key)
        except KeyError:
            raise HTTPException(HTTPStatus.NOT_FOUND, f'Profile for {pid} does not exist.')
        except Exception as e:
            logger.error('', exc_info=e)
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Error getting profile for process {pid}.')
        return {
                'pid': process.tgid,
                'tid': process.pid,
                'count': process.count,
                'total_lfc': process.total_lfc,
                'max_lfc': process.max_lfc,
                'profile': profile,
                }

    @staticmethod
    @app.get('/settings/{setting}')
    def get_setting(setting: EBPH_SETTINGS) -> Dict:
        """
        Get an ebpH setting.
        """
        value = API.bpf_program.get_setting(setting)
        if value is None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'No such setting {setting}.')
        return {'setting': setting, 'value': value}

    @staticmethod
    @app.put('/settings/{setting}/{value}')
    def change_setting(setting: EBPH_SETTINGS, value: int = Path(..., ge=0)) -> Dict:
        """
        Change an ebpH setting.
        """
        res = API.bpf_program.change_setting(setting, value)
        if res < 0:
            raise HTTPException(HTTPStatus.BAD_REQUEST, f'Unable to change {setting} to {value}.')
        return API.get_setting(setting)
