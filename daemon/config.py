import os, sys

class Config():
    socketdir = '/run'

    daemon_socket_adr = os.path.join(socketdir, 'ebphd.sock')
    daemon_pid_file = os.path.join(socketdir, 'ebphd.pid')
