
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import requests
import json
import httplib

class CordTesterWebClient(object):

    def __init__(self, host = 'localhost', port = 5000):
        self.host = host
        self.port = port
        self.rest = 'http://{}:{}'.format(self.host, self.port)

    def get_config(self, test_case):
        rest_uri = '{}/get'.format(self.rest)
        config = { 'test_case' : test_case }
        resp = requests.get(rest_uri, data = json.dumps(config))
        if resp.ok and resp.status_code == 200:
            config = resp.json()
            return config
        return None

    def set_config(self, test_case, test_config):
        rest_uri = '{}/update'.format(self.rest)
        config = { 'test_case' : test_case, 'config' : test_config }
        resp = requests.post(rest_uri, data = json.dumps(config))
        return resp.ok, resp.status_code

    def restore_config(self, test_case):
        rest_uri = '{}/restore'.format(self.rest)
        config = { 'test_case' : test_case }
        resp = requests.post(rest_uri, data = json.dumps(config))
        return resp.ok, resp.status_code

    def start(self, manifest = 'manifest.json'):
        rest_uri = '{}/start'.format(self.rest)
        config = { 'manifest' : manifest }
        resp = requests.post(rest_uri, data = json.dumps(config))
        return resp.ok, resp.status_code

    def cleanup(self, manifest = 'manifest.json'):
        rest_uri = '{}/cleanup'.format(self.rest)
        config = { 'manifest' : manifest }
        resp = requests.post(rest_uri, data = json.dumps(config))
        return resp.ok, resp.status_code

    def test(self, test, manifest = 'manifest.json', test_config = None):
        rest_uri = '{}/test'.format(self.rest)
        config = { 'manifest' : manifest, 'test' : test }
        if test_config:
            config['config'] = test_config
        resp = requests.post(rest_uri, data = json.dumps(config))
        return resp.ok, resp.status_code

class Tester(CordTesterWebClient):

    def __init__(self, host = 'localhost', port = 5000):
        super(Tester, self).__init__(host = host, port = port)

    def execute(self, test_case, manifest = 'manifest.json', test_config = None):
        print('Executing test %s' %test_case)
        _, status = self.start(manifest = manifest)
        assert status == httplib.OK, 'Test setup failed with status code %d' %status
        _, status = self.test(test_case, manifest = manifest, test_config = test_config)
        assert status == httplib.OK, 'Test run for test %s failed with status %d' %(test_case, status)
        _, status = self.cleanup(manifest = manifest)
        assert status == httplib.OK, 'Test cleanup failed with status %d' %status
        print('Test executed successfully')

if __name__ == '__main__':
    tester = Tester()
    tests = ('tls', 'igmp',)
    for test in tests:
        print('Getting config for test %s' %test)
        config = tester.get_config(test)
        print('%s' %config)

    tls_cfg = { 'VOLTHA_OLT_MAC' : '00:0c:e2:31:10:00' }
    igmp_cfg = { 'PORT_RX_DEFAULT' : 1, 'PORT_TX_DEFAULT' : 2, 'IGMP_TEST_TIMEOUT' : 10 }
    manifest = 'manifest-ponsim.json'
    tests = ( ('tls:eap_auth_exchange.test_eap_tls', tls_cfg, manifest),
              ('igmp:igmp_exchange.test_igmp_join_verify_traffic', igmp_cfg, manifest),
              )

    print('Setting up the test with %s' %manifest)
    _, status = tester.start(manifest = manifest)
    assert status == httplib.OK, 'Test setup failed with status code %d' %status

    for t, cfg, m in tests:
        _, status = tester.test(t, manifest = m, test_config = cfg)
        if status != httplib.OK:
            print('Test case %s failed with status code %d' %(t, status))
        else:
            print('Test case %s executed successfully' %t)

    print('Cleaning up the test with %s' %manifest)
    tester.cleanup(manifest = manifest)
