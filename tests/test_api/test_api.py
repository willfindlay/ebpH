"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    Copyright (C) 2019-2020  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Test the ebpH API.

    2020-Jul-16  William Findlay  Created this.

    TODO: Add several more tests here for complete coverage.
"""

from pprint import pprint
from random import randint

from ebph import defs
from ebph.utils import ns_to_str, ns_to_delta_str
from ebph.structs import EBPH_SETTINGS

def test_get_status(client):
    """
    Test getting current status.
    """
    res = client.get('/status')

    assert res.status_code == 200

    body = res.json()
    assert body['Monitoring'] == True
    assert body['Anomaly Limit'] == defs.ANOMALY_LIMIT
    assert body['Normal Factor'] == f'{defs.NORMAL_FACTOR}/{defs.NORMAL_FACTOR_DEN}'
    assert body['Normal Wait'] == ns_to_delta_str(defs.NORMAL_WAIT)
    # TODO: parse and test process and profile counts

def test_get_set_settings(client):
    """
    Test getting and setting all ebpH settings through the API.
    """
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
    """
    Test getting and setting invalid ebpH settings through the API.
    """
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
