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

# Routes below this line -----------------------------------------

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

@app.route('/api/profiles/reset/<key>', methods=['PUT'])
def reset_profile(key):
    """
    Reset a profile's data.
    """
    ebphd.bpf_program.reset_profile(int(key))
    return get_profile(key)

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
