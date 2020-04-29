import logging

from flask import Flask, jsonify
from flask.logging import default_handler

from ebpH.logger import get_logger
from ebpH.ebphd import ebphd

app = Flask(__name__)
wzlog = logging.getLogger('werkzeug')
wzlog.disabled = True
app.logger.disabled = True

logger = get_logger()

# Routes below this line -----------------------------------------

@app.route('/api/profiles')
def get_profiles():
    return jsonify(ebphd.bpf_program.get_profiles())
