from fastapi.testclient import TestClient
import pytest

from ebph.api import app, API

@pytest.fixture(scope='function')
def bpf_program_with_client(bpf_program):
    client = TestClient(app)
    API.connect_bpf_program(bpf_program)

    yield bpf_program, client
