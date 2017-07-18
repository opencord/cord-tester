from webserver import app
from flask import request, jsonify
import httplib
import json
import os
import sys

class CordTesterWebConfig(object):
    our_path = os.path.dirname(os.path.realpath(__file__))
    test_base = os.path.realpath(os.path.join(our_path, '..', '..'))

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
                os.rename(self.test_config, '{}.save'.format(self.test_config))
            for k, v in config.iteritems():
                cur_config[k] = v
                with open(self.test_config, 'w') as f:
                    json.dump(cur_config, f, indent = 4)
            return True
        return False

    def restore(self):
        if self.test_config:
            if os.access(self.test_config, os.F_OK):
                restore_file = '{}.save'.format(self.test_config)
                if os.access(restore_file, os.F_OK):
                    os.rename(restore_file, self.test_config)
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
