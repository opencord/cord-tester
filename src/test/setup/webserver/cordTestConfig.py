
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


from webserver import app
from flask import request, jsonify
import httplib
import json
import os
import sys
import copy

class CordTesterRun(object):
    our_path = os.path.dirname(os.path.realpath(__file__))
    exec_base = os.path.realpath(os.path.join(our_path, '..'))

    @classmethod
    def start(cls, manifest):
        status = False
        manifest_file = os.path.join(cls.exec_base, manifest)
        if os.access(manifest_file, os.F_OK):
            cmd = 'sudo {}/cord-test.py setup -m {}'.format(cls.exec_base, manifest_file)
            ret = os.system(cmd)
            status = True if ret == 0 else False

        return status

    @classmethod
    def cleanup(cls, manifest):
        status = False
        manifest_file = os.path.join(cls.exec_base, manifest)
        if os.access(manifest_file, os.F_OK):
            cmd = 'sudo {}/cord-test.py cleanup -m {}'.format(cls.exec_base, manifest_file)
            os.system(cmd)
            status = True

        return status

    @classmethod
    def test(cls, manifest, test, config = None):
        manifest_file = os.path.join(cls.exec_base, manifest)
        if not os.access(manifest_file, os.F_OK):
            return False
        #get test case as we could give a specific test to execute within a test case
        test_case = test.split(':')[0]
        cordWeb = CordTesterWebConfig(test_case)
        if config:
            status = cordWeb.update(config)
            #test case is invalid
            if status is False:
                return status
        cmd = 'sudo {}/cord-test.py run -m {} -t {}'.format(cls.exec_base, manifest_file, test)
        ret = os.system(cmd)
        status = True if ret == 0 else False
        if config:
            cordWeb.restore()
        return status

class CordTesterWebConfig(object):
    our_path = os.path.dirname(os.path.realpath(__file__))
    test_base = os.path.realpath(os.path.join(our_path, '..', '..'))
    restore_config = {}

    def __init__(self, test_case):
        self.test_case = test_case
        self.test_path = None
        self.test_config = None
        test_path = os.path.join(self.test_base, self.test_case)
        if os.path.isdir(test_path):
            self.test_path = test_path
            self.test_config = os.path.join(self.test_path, '{}Test.json'.format(self.test_case))

    def update(self, config):
        cur_config = {}
        if self.test_config:
            if os.access(self.test_config, os.F_OK):
                with open(self.test_config, 'r') as f:
                    cur_config = json.load(f)
                self.save(copy.copy(cur_config))
            for k, v in config.iteritems():
                cur_config[k] = v
                with open(self.test_config, 'w') as f:
                    json.dump(cur_config, f, indent = 4)
            return True
        return False

    def save(self, cur_config):
        self.restore_config[self.test_case] = cur_config

    def restore(self):
        config = None
        if self.test_config:
            if self.test_case in self.restore_config:
                config = self.restore_config[self.test_case]
                with open(self.test_config, 'w') as f:
                    json.dump(config, f, indent = 4)
                return True

        return False

    def get(self):
        cur_config = {}
        if self.test_config:
            if os.access(self.test_config, os.F_OK):
                with open(self.test_config) as f:
                    cur_config = json.load(f)
        return cur_config

@app.route('/')
@app.route('/index')
def index():
    return 'Welcome to Cord Tester configuration page'

@app.route('/get')
def get():
    data = request.get_json(force = True)
    test_case = data.get('test_case', None)
    if test_case:
        cordWeb = CordTesterWebConfig(test_case)
        config = cordWeb.get()
        return jsonify(config)
    return ('', httplib.NOT_FOUND)

@app.route('/update', methods = ['POST'])
def update():
    data = request.get_json(force = True)
    test_case = data.get('test_case', None)
    config = data.get('config', None)
    response = ('', httplib.NOT_FOUND)
    if test_case:
        cordWeb = CordTesterWebConfig(test_case)
        status = cordWeb.update(config)
        if status:
            response = ('', httplib.OK)

    return response

@app.route('/restore', methods = ['POST'])
def restore():
    data = request.get_json(force = True)
    test_case = data.get('test_case', None)
    response = ('', httplib.NOT_FOUND)
    if test_case:
        cordWeb = CordTesterWebConfig(test_case)
        status = cordWeb.restore()
        if status:
            response = ('', httplib.OK)
    return response

@app.route('/start', methods = ['POST'])
def start():
    data = request.get_json(force = True)
    manifest = data.get('manifest', 'manifest.json')
    status = CordTesterRun.start(manifest)
    if status:
        return ('', httplib.OK)
    return ('', httplib.NOT_ACCEPTABLE)

@app.route('/cleanup', methods = ['POST'])
def cleanup():
    data = request.get_json(force = True)
    manifest = data.get('manifest', 'manifest.json')
    status = CordTesterRun.cleanup(manifest)
    if status:
        return ('', httplib.OK)
    return ('', httplib.NOT_ACCEPTABLE)

@app.route('/test', methods = ['POST'])
def test():
    data = request.get_json(force = True)
    manifest = data.get('manifest', 'manifest.json')
    test = data.get('test', None)
    config = data.get('config', None)
    if test is None:
        return ('', httplib.NOT_FOUND)
    status = CordTesterRun.test(manifest, test, config = config)
    if status:
        return ('', httplib.OK)
    return ('', httplib.NOT_ACCEPTABLE)
