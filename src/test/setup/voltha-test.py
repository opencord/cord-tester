#!/usr/bin/env python

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
from argparse import ArgumentParser
import os
import sys
utils_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../utils')
cli_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../cli')
sys.path.append(utils_dir)
sys.path.append(cli_dir)
sys.path.insert(1, '/usr/local/lib/python2.7/dist-packages')
from CordTestUtils import getstatusoutput
import time
import requests
import httplib
import json
import signal

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


class CordTesterWeb(object):

    def __init__(self, args, start_in = 3):
        self.args = args
        self.tester = Tester()
        self.start_in = start_in

    def run(self):
        manifest = self.args.manifest
        olt_type = self.args.olt_type
        test_type = self.args.test_type
        disable_teardown = self.args.disable_teardown
        test_mode = self.args.test_mode
        disable_cleanup = self.args.disable_cleanup
        if test_mode is True:
            disable_cleanup = True
        test_config = { 'VOLTHA_HOST' : self.args.voltha_host,
                        'VOLTHA_OLT_TYPE' : self.args.olt_type,
                        'VOLTHA_TEARDOWN' : not disable_teardown,
                        }
        if olt_type.startswith('tibit'):
            test_config['VOLTHA_OLT_MAC'] = self.args.olt_arg
        elif olt_type.startswith('maple'):
            test_config['VOLTHA_OLT_IP'] = self.args.olt_arg
        elif olt_type.startswith('ponsim'):
            test_config['VOLTHA_PONSIM_HOST'] = self.args.olt_arg
        else:
            print('Unsupported OLT type %s' %olt_type)
            return 127

        if self.start_in:
            time.sleep(self.start_in)

        if test_mode is False:
            _, status = self.tester.start(manifest = manifest)
            assert status == httplib.OK, 'Test setup failed with status %d' %status

        for test in test_type.split(','):
            print('Running test case %s' %(test))
            _, status = self.tester.test(test, manifest = manifest, test_config = test_config)
            if status != httplib.OK:
                print('Test case %s failed with status code %d' %(test, status))

        if disable_cleanup is False:
            print('Cleaning up the test')
            self.tester.cleanup(manifest = manifest)
        return 0 if status == httplib.OK else 127

class CordTesterWebServer(object):

    server_path = os.path.dirname(os.path.realpath(__file__))
    server = 'webserver-run.py'
    pattern = 'pgrep -f "python ./{}"'.format(server)

    def running(self):
        st, _ = getstatusoutput(self.pattern)
        return True if st == 0 else False

    def kill(self):
        st, output = getstatusoutput(self.pattern)
        if st == 0 and output:
            pids = output.strip().splitlines()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except:
                    pass

    def start(self):
        if self.running() is False:
            print('Starting CordTester Web Server')
            cmd = 'cd {} && python ./{} &'.format(self.server_path, self.server)
            os.system(cmd)

def run_test(args):
    testWebServer = CordTesterWebServer()
    testWebServer.start()
    testWeb = CordTesterWeb(args, start_in = 3)
    status = testWeb.run()
    testWebServer.kill()
    return status

if __name__ == '__main__':
    parser = ArgumentParser(description = 'VOLTHA tester')
    parser.add_argument('-test-type', '--test-type', default = 'tls:eap_auth_exchange.test_eap_tls', help = 'Test type to run')
    parser.add_argument('-manifest', '--manifest', default='manifest-voltha.json', help = 'Manifest file to use')
    parser.add_argument('-voltha-host', '--voltha-host', default='172.17.0.1', help = 'VOLTHA host ip')
    parser.add_argument('-olt-type', '--olt-type', default = 'ponsim_olt', help = 'OLT type')
    parser.add_argument('-olt-arg', '--olt-arg', default = '172.17.0.1', help = 'OLT type argument')
    parser.add_argument('-disable-teardown', '--disable-teardown', action='store_true', help = 'Disable VOLTHA teardown')
    parser.add_argument('-disable-cleanup', '--disable-cleanup', action='store_true', help = 'Dont cleanup cord-tester')
    parser.add_argument('-test-mode', '--test-mode', action='store_true',
                        help = 'Directly run the cord-tester run-test phase without setup and cleanup')

    parser.set_defaults(func = run_test)
    args = parser.parse_args()
    res = args.func(args)
    sys.exit(res)
