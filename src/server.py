import os, sys
import logging
import socket
import socketserver
import struct
import json
from http import HTTPStatus as Status

import config
from utils import to_json_bytes, from_json_bytes

logger = logging.getLogger('ebpH')

class EBPHDispatchError(Exception): pass

class EBPHRequestDispatcher:
    """
    Dispatches requests in the form of {func, [args], [kwargs]} received by server to daemon.
    Register functions with register.
    """
    def __init__(self, daemon):
        self.daemon = daemon
        self.funcs = {}

    def register(self, func):
        """
        Register a function with the dispatcher.
        """
        self.funcs[func.__name__] = func

    def dispatch_request(self, request):
        """
        Attempt to call the requested function.
        """
        try:
            func = request['func']

            try:
                args = request['args']
            except KeyError:
                args = None

            try:
                kwargs = request['kwargs']
            except KeyError:
                kwargs = None

            # Set defaults
            if args == None:
                args = []
            if kwargs == None:
                kwargs = {}

            return self.funcs[func](*args, **kwargs)
        except KeyError:
            raise EBPHDispatchError(f'"{func}" is not registered with request dispatcher')

class EBPHUnixStreamServer(socketserver.ThreadingUnixStreamServer):
    def __init__(self, request_dispatcher):
        super().__init__(server_address=config.socket, RequestHandlerClass=EBPHStreamRequestHandler)
        self.daemon_threads = True
        self.request_dispatcher = request_dispatcher

    # Bind socket
    def server_bind(self):
        # Make sure socket doesn't already exist
        try:
            os.unlink(self.server_address)
        except OSError as e:
            if os.path.exists(self.server_address):
                raise Exception("Socket path already exists but couldn't unlink...")

        # Init socket
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Set appropriate permissions for socket
        old_umask = os.umask(0o177)
        # Bind socket
        self.socket.bind(self.server_address)
        self.socket.listen()
        # Restore old umask
        os.umask(old_umask)

    # Verify a request
    # TODO: just returning true for now, should change this to implement access control, request checking, etc.
    def verify_request(self, request, client_address):
        return True

class EBPHStreamRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            try:
                # Send json-encoded response
                self.response = to_json_bytes(self.response)
                self.request.send(self.response)
            except AttributeError:
                pass # Do nothing before first iteration

            self.response = {'code': Status.OK, 'message': None}

            # Receive data
            self.data = self.request.recv(config.socket_buff_size)
            if not self.data:
                break
            self.data = self.data.strip()
            try:
                self.data = from_json_bytes(self.data)
            except json.JSONDecodeError as e:
                logger.error(f"Could not decode JSON object: {e}")
                self.response['code'] = Status.INTERNAL_SERVER_ERROR
                continue

            try:
                self.response['message'] = self.server.request_dispatcher.dispatch_request(self.data)
            except EBPHDispatchError as e:
                logger.error(f"Could not dispatch request to function call: {e}")
                self.response['code'] = Status.INTERNAL_SERVER_ERROR
                continue
            except Exception as e:
                logger.error(f"Unable to complete request: {e}")
                self.response['code'] = Status.INTERNAL_SERVER_ERROR
                continue
