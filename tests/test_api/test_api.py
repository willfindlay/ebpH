from pprint import pprint
from random import randint

from ebph import defs
from ebph.utils import ns_to_str, ns_to_delta_str
from ebph.structs import EBPH_SETTINGS

def test_get_status(client):
    res = client.get('/status')

    assert res.status_code == 200

    body = res.json()
    assert body['Monitoring'] == True
    assert body['Anomaly Limit'] == defs.ANOMALY_LIMIT
    assert body['Normal Factor'] == f'{defs.NORMAL_FACTOR}/{defs.NORMAL_FACTOR_DEN}'
    assert body['Normal Wait'] == ns_to_delta_str(defs.NORMAL_WAIT)

def test_get_set_settings(client):
    for setting in EBPH_SETTINGS:
        for _ in range(100):
            value = randint(0, 2 ** 64 - 1)

            res = client.put(f'/settings/{setting}/{value}')
            assert res.status_code == 200
            set_json = res.json()

            res = client.get(f'/settings/{setting}')
            assert res.status_code == 200
            get_json = res.json()

            assert get_json == set_json

def test_get_set_invalid_settings(client):
    for setting in EBPH_SETTINGS:
        for _ in range(100):
            value = randint(-(2 ** 64 - 1), -1)

            res = client.get(f'/settings/{setting}')
            assert res.status_code == 200
            orig_json = res.json()

            res = client.put(f'/settings/{setting}/{value}')
            assert res.status_code != 200

            res = client.get(f'/settings/{setting}')
            assert res.status_code == 200
            curr_json = res.json()

            assert orig_json == curr_json
