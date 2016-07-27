#
# Copyright 2016-present Ciena Corporation
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
#
import json
import requests
import os,sys,time
from OltConfig import OltConfig
import fcntl, socket, struct

def get_mac(iface = 'ovsbr0', pad = 4):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(iface[:15])))
    except:
        info = ['0'] * 24
    s.close()
    sep = ''
    if pad == 0:
        sep = ':'
    return '0'*pad + sep.join(['%02x' %ord(char) for char in info[18:24]])

class OnosCtrl:

    auth = ('karaf', 'karaf')
    controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
    cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
    maven_repo = 'http://central.maven.org/maven2/org/onosproject'
    applications_url = 'http://%s:8181/onos/v1/applications' %(controller)
    host_cfg_url = 'http://%s:8181/onos/v1/hosts/' %(controller)

    def __init__(self, app, controller = None):
        self.app = app
        if controller is not None:
            self.controller = controller
        self.app_url = 'http://%s:8181/onos/v1/applications/%s' %(self.controller, self.app)
        self.cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(self.controller)
        self.auth = ('karaf', 'karaf')

    @classmethod
    def config(cls, config):
        if config:
            json_data = json.dumps(config)
            resp = requests.post(cls.cfg_url, auth = cls.auth, data = json_data)
            return resp.ok, resp.status_code
        return False, 400

    def activate(self):
        resp = requests.post(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code

    def deactivate(self):
        resp = requests.delete(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code

    @classmethod
    def get_devices(cls):
        url = 'http://%s:8181/onos/v1/devices' %(cls.controller)
        result = requests.get(url, auth = cls.auth)
        if result.ok:
            devices = result.json()['devices']
            return filter(lambda d: d['available'], devices)

        return None

    @classmethod
    def get_device_id(cls):
        '''If running under olt, we get the first switch connected to onos'''
        olt = OltConfig()
        did = 'of:' + get_mac('ovsbr0')
        if olt.on_olt():
            devices = cls.get_devices()
            if devices:
                dids = map(lambda d: d['id'], devices)
                if len(dids) == 1:
                    did = dids[0]
                else:
                    ###If we have more than 1, then check for env before using first one
                    did = os.getenv('OLT_DEVICE_ID', dids[0])

        return did

    @classmethod
    def get_flows(cls, device_id):
        url = 'http://%s:8181/onos/v1/flows/' %(cls.controller) + device_id
        result = requests.get(url, auth = cls.auth)
        if result.ok:
            return result.json()['flows']
        return None

    @classmethod
    def cord_olt_config(cls, olt_device_data = None):
        '''Configures OLT data for existing devices/switches'''
        if olt_device_data is None:
            return
        did_dict = {}
        config = { 'devices' : did_dict }
        devices = cls.get_devices()
        if not devices:
            return
        device_ids = map(lambda d: d['id'], devices)
        for did in device_ids:
            access_device_dict = {}
            access_device_dict['accessDevice'] = olt_device_data
            did_dict[did] = access_device_dict

        ##configure the device list with access information
        return cls.config(config)

    @classmethod
    def install_app(cls, app_file, onos_ip = None):
        params = {'activate':'true'}
        headers = {'content-type':'application/octet-stream'}
        url = cls.applications_url if onos_ip is None else 'http://{0}:8181/onos/v1/applications'.format(onos_ip)
        with open(app_file, 'rb') as payload:
            result = requests.post(url, auth = cls.auth,
                                   params = params, headers = headers,
                                   data = payload)
        return result.ok, result.status_code

    @classmethod
    def install_app_from_url(cls, app_name, app_version, app_url = None, onos_ip = None):
        params = {'activate':'true'}
        headers = {'content-type':'application/json'}
        if app_url is None:
            app_oar_file = '{}-{}.oar'.format(app_name, app_version)
            app_url = '{0}/{1}/{2}/{3}'.format(cls.maven_repo, app_name, app_version, app_oar_file)
        params['url'] = app_url
        url = cls.applications_url if onos_ip is None else 'http://{0}:8181/onos/v1/applications'.format(onos_ip)
        result = requests.post(url, auth = cls.auth,
                               json = params, headers = headers)
        return result.ok, result.status_code

    @classmethod
    def uninstall_app(cls, app_name, onos_ip = None):
        params = {'activate':'true'}
        headers = {'content-type':'application/octet-stream'}
        url = cls.applications_url if onos_ip is None else 'http://{0}:8181/onos/v1/applications'.format(onos_ip)
        app_url = '{}/{}'.format(url, app_name)
        resp = requests.delete(app_url, auth = cls.auth)
        return resp.ok, resp.status_code

    @classmethod
    def host_config(cls, config):
        if config:
           json_data = json.dumps(config)
           resp = requests.post(cls.host_cfg_url, auth = cls.auth, data = json_data)
           return resp.ok, resp.status_code
        return False, 400
