import logging
from http import HTTPStatus

from flask import Flask, jsonify, request
from flask.logging import default_handler

from ebpH.logger import get_logger
from ebpH.ebphd import ebphd

app = Flask(__name__)
wzlog = logging.getLogger('werkzeug')
wzlog.disabled = True
app.logger.disabled = True

logger = get_logger()

# Profile queries below this line -----------------------------------------

@app.route('/api/profiles', methods=['GET'])
def get_profiles():
    """
    Return a list of all profiles and associated data, without lookahead pairs.
    """
    return jsonify(ebphd.bpf_program.get_profiles())

@app.route('/api/profiles/<key>', methods=['GET'])
def get_profile(key):
    """
    Return a specific profile and associated data, without lookahead pairs.
    """
    profile = ebphd.bpf_program.get_profile(int(key))
    if not profile:
        return jsonify(profile), HTTPStatus.BAD_REQUEST
    return jsonify(profile), HTTPStatus.OK

# Profile operations below this line --------------------------------------

@app.route('/api/profiles/reset/<key>', methods=['PUT'])
def reset_profile(key):
    """
    Reset a profile's data.
    """
    ebphd.bpf_program.reset_profile(int(key))
    return get_profile(key)

@app.route('/api/profiles/normalize/<key>', methods=['PUT'])
def normalize_profile(key):
    """
    Normalize a profile by key.
    """
    ebphd.bpf_program.normalize_profile(int(key))
    return get_profile(key)

# Process queries below this line -----------------------------------------

@app.route('/api/processes', methods=['GET'])
def get_processes():
    """
    Return a list of all processes and associated profiles.
    """
    return jsonify(ebphd.bpf_program.get_processes())

@app.route('/api/processes/<pid>', methods=['GET'])
def get_process(pid):
    """
    Return a specific process and associated profile.
    """
    process = ebphd.bpf_program.get_process(int(pid))
    if not process:
        return jsonify(process), HTTPStatus.BAD_REQUEST
    return jsonify(process), HTTPStatus.OK

# Process operations below this line --------------------------------------

@app.route('/api/processes/normalize/<tid>', methods=['PUT'])
def normalize_process(tid):
    """
    Normalize a process' associated profile.
    """
    ebphd.bpf_program.normalize_process(int(tid))
    return get_process(tid)

# Settings below this line ------------------------------------------------

@app.route('/api/settings/log-sequences', methods=['PUT'])
def log_sequences():
    """
    Return a specific process and associated profile.
    """
    try:
        should_log = int(request.values['should_log'])
    except:
        return 'Unable to parse value for should_log', HTTPStatus.BAD_REQUEST
    res = ebphd.bpf_program.set_logging_new_sequences(should_log)
    return jsonify(res)
