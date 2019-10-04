import os, sys
from ebphd.ebph import ebpHD
from ebphd.config import Config

config.init()

daemon = ebphd()

@fixture
def teardown():
    yield
    daemon.stop()

def test_daemon(teardown):
    assert 1 == 1
