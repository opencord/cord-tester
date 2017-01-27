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

def get_mac(iface = None, pad = 4):
    if iface is None:
        iface = os.getenv('TEST_SWITCH', 'ovsbr0')
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

def get_controller():
    controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
    controller = controller.split(',')[0]
    return controller

class OnosCtrl:

    auth = ('karaf', 'karaf')
    controller = get_controller()
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
    def config(cls, config, controller=None):
        if config is not None:
            json_data = json.dumps(config)
	    if controller is None:
                resp = requests.post(cls.cfg_url, auth = cls.auth, data = json_data)
	    else:
		cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
	        resp = requests.post(cfg_url, auth = cls.auth, data = json_data)
            return resp.ok, resp.status_code
        return False, 400

    @classmethod
    def get_config(cls, controller=None):
	if controller is None:
            controller = cls.controller
	cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
	resp = requests.get(cfg_url, auth = cls.auth)
        if resp.ok:
            return resp.json()
        return None

    @classmethod
    def delete(cls, config, controller=None):
        if config:
            json_data = json.dumps(config)
	    if controller is None:
	        print('default Onos config url is %s'%cls.cfg_url)
                resp = requests.delete(cls.cfg_url, auth = cls.auth, data = json_data)
	    else:
		cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
	        resp = requests.delete(cfg_url, auth = cls.auth, data = json_data)
            return resp.ok, resp.status_code
        return False, 400

    def activate(self):
        resp = requests.post(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code

    def deactivate(self):
        resp = requests.delete(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code

    @classmethod
    def get_devices(cls, controller = None):
        if controller is None:
            controller = cls.controller
        url = 'http://%s:8181/onos/v1/devices' %(controller)
        result = requests.get(url, auth = cls.auth)
        if result.ok:
            devices = result.json()['devices']
            return filter(lambda d: d['available'], devices)

        return None

    @classmethod
    def get_device_id(cls, controller = None):
        '''If running under olt, we get the first switch connected to onos'''
        olt = OltConfig()
        did = 'of:' + get_mac()
        if olt.on_olt():
            devices = cls.get_devices(controller = controller)
            if devices:
                dids = map(lambda d: d['id'], devices)
                if len(dids) == 1:
                    did = dids[0]
                else:
                    ###If we have more than 1, then check for env before using first one
                    did = os.getenv('OLT_DEVICE_ID', dids[0])

        return did

    @classmethod
    def get_device_ids(cls, controller = None):
        '''If running under olt, we get the first switch connected to onos'''
        olt = OltConfig()
        did = 'of:' + get_mac()
        device_ids = []
        if olt.on_olt():
            devices = cls.get_devices(controller = controller)
            if devices:
                device_ids = map(lambda d: d['id'], devices)
        else:
            device_ids.append(did)

        return device_ids

    @classmethod
    def get_flows(cls, device_id,controller=None):
        if controller is None:
	    url = 'http://%s:8181/onos/v1/flows/' %(cls.controller) + device_id
	else:
	    url = 'http://%s:8181/onos/v1/flows/' %(controller) + device_id
        result = requests.get(url, auth = cls.auth)
        if result.ok:
            return result.json()['flows']
        return None

    @classmethod
    def get_ports_device(cls, device_id, controller = None):
        if controller is None:
            url = 'http://{}:8181/onos/v1/devices/{}/ports'.format(cls.controller, device_id)
        else:
            url = 'http://{}:8181/onos/v1/devices/{}/ports'.format(controller, device_id)

        result = requests.get(url, auth = cls.auth)
        if result.ok:
            return result.json()['ports']
        return None

    @classmethod
    def cord_olt_device_map(cls, olt_config, controller = None):
        olt_device_list = []
        olt_port_map, _ = olt_config.olt_port_map()
        switches = olt_port_map['switches']
        if len(switches) > 1:
            device_ids = cls.get_device_ids(controller = controller)
        else:
            did = cls.get_device_id(controller = controller)
            if did is None:
                return olt_device_list
            uplink_dict = {}
            uplink_dict['did'] = did
            uplink_dict['switch'] = switches[0]
            uplink_dict['uplink'] = str(olt_config.olt_conf['uplink'])
            uplink_dict['vlan'] = str(olt_config.olt_conf['vlan'])
            olt_device_list.append(uplink_dict)
            return olt_device_list

        for did in device_ids:
            ports = cls.get_ports_device(did, controller = controller)
            if ports:
                matched = False
                for port in ports:
                    for switch in switches:
                        if port['annotations']['portName'] == switch:
                            uplink_dict = {}
                            uplink = olt_port_map[switch]['uplink']
                            uplink_dict['did'] = did
                            uplink_dict['switch'] = switch
                            uplink_dict['uplink'] = str(uplink)
                            uplink_dict['vlan'] = str(olt_config.olt_conf['vlan'])
                            olt_device_list.append(uplink_dict)
                            matched = True
                            break
                    if matched == True:
                        break

        return olt_device_list

    @classmethod
    def cord_olt_config(cls, olt_config, controller=None):
        '''Configures OLT data for existing devices/switches'''
        did_dict = {}
        config = { 'devices' : did_dict }
        olt_device_list = cls.cord_olt_device_map(olt_config, controller = controller)
        if not olt_device_list:
            return
        for olt_map in olt_device_list:
            access_device_dict = {}
            device_data = {'uplink': olt_map['uplink'], 'vlan': olt_map['vlan']}
            access_device_dict['accessDevice'] = device_data
            did_dict[olt_map['did']] = access_device_dict

        ##configure the device list with access information
        return cls.config(config, controller=controller)

    @classmethod
    def install_app(cls, app_file, onos_ip = None):
        params = {'activate':'true'}
        headers = {'content-type':'application/octet-stream'}
        url = cls.applications_url if onos_ip is None else 'http://{0}:8181/onos/v1/applications'.format(onos_ip)
        with open(app_file, 'rb') as payload:
            result = requests.post(url, auth = cls.auth,
                                   params = params, headers = headers,
                                   data = payload)
	print('result.ok, result.status_code are %s and %s'%(result.ok, result.status_code))
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
    def host_config(cls, config,onos_ip=None):
        if config:
           json_data = json.dumps(config)
	   url = cls.host_cfg_url if onos_ip is None else 'http://%s:8181/onos/v1/hosts/'.format(onos_ip)
           resp = requests.post(cls.host_cfg_url, auth = cls.auth, data = json_data)
           return resp.ok, resp.status_code
        return False, 400
