from fastapi.testclient import TestClient
import pytest

from ebph.api import app, API

@pytest.fixture(scope='function')
def client(bpf_program):
    client = TestClient(app)
    API.connect_bpf_program(bpf_program)

    yield client
