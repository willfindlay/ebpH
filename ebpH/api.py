import logging

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
    return jsonify(ebphd.bpf_program.get_profiles())

@app.route('/api/profiles/<key>', methods=['GET'])
def get_profile(key):
    return jsonify(ebphd.bpf_program.get_profile(int(key)))

@app.route('/api/profiles/<key>/reset', methods=['PUT'])
def reset_profile(key):
    return jsonify(ebphd.bpf_program.reset_profile(int(key)))
