from pprint import pprint

from ebph import defs
from ebph.utils import ns_to_str, ns_to_delta_str

def test_get_status_empty(bpf_program_with_client):
    bpf_program, client = bpf_program_with_client

    res = client.get('/status')

    assert res.status_code == 200

    body = res.json()
    assert body['Monitoring'] == True
    assert body['Anomaly Limit'] == defs.ANOMALY_LIMIT
    assert body['Normal Factor'] == f'{defs.NORMAL_FACTOR}/{defs.NORMAL_FACTOR_DEN}'
    assert body['Normal Wait'] == ns_to_delta_str(defs.NORMAL_WAIT)
